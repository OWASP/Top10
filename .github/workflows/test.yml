name: Test
on:
  push:
  pull_request:
  schedule: [{cron: '0 0 10 * *'}] # monthly https://crontab.guru/#0_0_10_*_*
  workflow_dispatch:

permissions: read-all

jobs:
  test:
    uses: nodenv/.github/.github/workflows/test.yml@v4
    permissions:
      contents: read
      packages: read
      id-token: write
      security-events: write
      statuses: write
