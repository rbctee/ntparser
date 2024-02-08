package cmd

// https://stackoverflow.com/questions/33701828/simple-way-of-getting-key-depending-on-value-from-hashmap-in-golang
func MapKey(m map[string]uint8, value uint8) string {
	for k, v := range m {
		if v == value {
			return k
		}
	}
	return ""
}

func IsBitSet(integer int, bitIndex uint) bool {
	val := integer >> int(bitIndex)
	return (val & 1) == 1
}
