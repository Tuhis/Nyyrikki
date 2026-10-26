package canary

import "golang.org/x/text/language"

// language.ParseAcceptLanguage in golang.org/x/text < 0.3.8 is GO-2022-1059.
func Bad(s string) ([]language.Tag, []float32, error) { return language.ParseAcceptLanguage(s) }
