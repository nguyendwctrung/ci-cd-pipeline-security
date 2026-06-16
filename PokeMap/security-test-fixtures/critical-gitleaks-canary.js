/*
 * INTENTIONAL SECURITY SCANNER TEST - DO NOT USE IN RUNTIME.
 *
 * This file is a temporary, fake Gitleaks canary for validating the CI/CD
 * security pipeline on a test branch. The values below are not real
 * credentials and must be removed after the GitHub Actions test run.
 */

const fakeAwsAccessKeyId = "AKIAIOSFODNN7EXAMPLE";
const fakeAwsSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const fakeGithubToken = "ghp_000000000000000000000000000000000000";

module.exports = {
  fakeAwsAccessKeyId,
  fakeAwsSecretAccessKey,
  fakeGithubToken,
};
