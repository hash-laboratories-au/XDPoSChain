// A countdown timer that will mostly be used by XDPoS v2 consensus engine
package countdown

import (
	"sync"
	"time"

	"github.com/XinFinOrg/XDPoSChain/log"
)

type CountdownTimer struct {
	lock            sync.RWMutex // Protects the Initilised field
	resetc          chan int
	quitc           chan chan struct{}
	initilised      bool
	timeoutDuration time.Duration
	// Triggered when the countdown timer timeout for the `timeoutDuration` period, it will pass current timestamp to the callback function
	OnTimeoutFn func(time time.Time) error
}

func NewCountDown(duration time.Duration) *CountdownTimer {
	return &CountdownTimer{
		resetc:          make(chan int),
		quitc:           make(chan chan struct{}),
		initilised:      false,
		timeoutDuration: duration,
	}
}

// Completely stop the countdown timer from running.
func (t *CountdownTimer) StopTimer() {
	q := make(chan struct{})
	t.quitc <- q
	<-q
}

// Reset will start the countdown timer if it's already stopped, or simply reset the countdown time back to the defual `duration`
func (t *CountdownTimer) Reset() {
	log.Info("Reset timmer")
	if !t.isInitilised() {
		t.setInitilised(true)
		go t.startTimer()
	} else {
		t.resetc <- 0
	}
}

// A long running process that
func (t *CountdownTimer) startTimer() {
	// Make sure we mark Initilised to false when we quit the countdown
	defer t.setInitilised(false)
	timer := time.NewTimer(t.timeoutDuration)
	// We start with a inf loop
	for {
		select {
		case q := <-t.quitc:
			log.Info("Quit countdown timer")
			close(q)
			return
		case <-timer.C:
			log.Info("Countdown time reached!")
			err := t.OnTimeoutFn(time.Now())
			if err != nil {
				log.Error("OnTimeoutFn error", err)
			}
		case <-t.resetc:
			log.Info("Reset countdown timer")
			timer.Reset(t.timeoutDuration)
		}
	}
}

// Set the desired value to Initilised with lock to avoid race condition
func (t *CountdownTimer) setInitilised(value bool) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.initilised = value
}

func (t *CountdownTimer) isInitilised() bool {
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.initilised
}
