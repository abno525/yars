//go:build !race

package db

// raceScale is 1 without the race detector: time limits hold as written.
const raceScale = 1
