package main

const (
	uploadUsage      = "Invalid upload options. Use upload --sbom FILE with --release-id ID, or --project-id ID --version VERSION, or --project-slug SLUG --version VERSION."
	uploadKey        = "Set CRACKEN_API_KEY to a valid API key in your environment."
	uploadURL        = "Set CRACKEN_API_URL or pass --api-url with an HTTPS API base URL. HTTP is allowed only for localhost."
	uploadFile       = "The SBOM must be a readable JSON file no larger than 16 MiB. ZIP files are not supported."
	uploadFormat     = "The SBOM format is not supported. Use CycloneDX JSON or SPDX JSON."
	uploadNetwork    = "The API request failed. Check the network connection and the API URL, then try again."
	uploadHTTP       = "The API returned HTTP %d."
	uploadInvalid    = "The API response is invalid."
	uploadAccepted   = "Upload accepted. Analysis: %s."
	uploadSucceeded  = "Analysis succeeded."
	uploadFailed     = "Analysis failed."
	uploadTimeout    = "Timed out waiting for the analysis."
	uploadFindings   = "Findings at or above the selected severity threshold were found."
	uploadNoFindings = "No findings at or above the selected severity threshold were found."
	uploadScope      = "The key needs permission to read findings to use --fail-on."
	uploadHeading    = "Send the SBOM to crAcken (optional)"
	uploadOffline    = "Generation stays offline. Only the upload command sends data to crAcken, and only the SBOM file you name, when you run it."
)
