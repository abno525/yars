//go:build race

package db

// raceScale stretches time limits under the race detector, which runs the
// pure-Go SQLite several times slower.
const raceScale = 10
