package engine

func buildGolden() ([]byte, error) {
	return BuildConfig(goldenLines(), testClients, nil, Options{APIPort: 10085})
}
