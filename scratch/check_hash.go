package main
import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)
func main() {
	key := "EyIT2fUt9o8VSMOZKdqG0hrsFgb6PD17"
	hash := sha256.Sum256([]byte(key))
	fmt.Println(hex.EncodeToString(hash[:]))
}
