package main

import "fmt"

func main() {
	items := []int{3}
	array := []int{1, 2, 3, 4, 5, 6}
	if len(items) == 0 {
		fmt.Println(array)
		return
	}

	for _, item := range items {
		for i := len(array) - 1; i >= 0; i-- {
			if array[i] == item {
				array = append(array[:i], array[i+1:]...)
			}
		}
	}
	fmt.Println(array)
	return
}
