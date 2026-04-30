# ACME Dev Runbook — staging environment

## Connecting to staging

Use the AWS CLI with the staging profile:

```
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

## GitHub Actions setup

Add the following secret to the repo's Actions secrets:

```
GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678
```

## API integration

If you need to call the staging Anthropic environment for testing:

```
ANTHROPIC_API_KEY=sk-ant-api03-fakeexamplekeydonotuseinrealdeploysxyz
```

## SSH access

The staging bastion key is included for convenience:

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
EXAMPLECONTENTNOTAREALKEYJUSTASTRINGTHATLOOKSLIKEAPEMBLOCKFOROURSCANNER
-----END OPENSSH PRIVATE KEY-----
```

## Database

```
DATABASE_URL=postgres://stage_user:Hunter2!@stage-db.acme.example.com:5432/stage
```
