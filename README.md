# Slack DLP Log Extractor

This script can be used to extract Slack DLP event logs from a Slack organisation in JSON format. These logs contain more data for DLP events than is provided in the standard Slack Audit logs or in the console. This workflow can be used to generate log data on DLP violations for ingestion into a SIEM or other log analysis tool, and can be useful for incident investigation and automated response.

## How it Works
The script uses an unofficial Slack API endpoint to retrieve DLP logs. It requires a valid `d` cookie for authentication. The script will paginate through the logs and output them to STDOUT in JSON format.

## Requirements
- Python 3.10 or higher
- Slack Enterprise subscription
- `d` cookie from a user with the `DLP Admin` role in the Enterprise 

Instructions on how to retrieve the `d` cookie can be found on my blog [here](https://www.papermtn.co.uk/retrieving-and-using-slack-cookies-for-authentication/)

> [!NOTE]
> Ensure the user account you recover the cookie from has the `DLP Admin` role in your Enterprise. Best practice is to create a dedicated service account for this purpose that otherwise has as few permissions as possible.

## Usage

```bash
usage: slack-dlp-log-extractor.py [-h] [--slack-cookie SLACK_COOKIE] [--enterprise-domain ENTERPRISE_DOMAIN] [--earliest EARLIEST] [--latest LATEST]

Slack DLP Logs Extractor

options:
  -h, --help            show this help message and exit
  --slack-cookie SLACK_COOKIE
                        Slack d cookie value (prefer env var D_COOKIE).
  --enterprise-domain ENTERPRISE_DOMAIN
                        Slack enterprise domain (prefer env var ENTERPRISE_DOMAIN).
  --earliest EARLIEST   Optional: earliest date_create epoch seconds
  --latest LATEST       Optional: latest date_create epoch seconds
```

1. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the script with the required arguments:
   ```bash
    python slack_dlp_log_extractor.py --slack-cookie $D_COOKIE --enterprise_domain $ENTERPRISE_DOMAIN
   ```

> [!NOTE]
> You can also set the `D_COOKIE` and `ENTERPRISE_DOMAIN` as environment variables to avoid passing them as command-line arguments. These are sensitive values, so ensure they are handled securely.

### Filtering by Date
You can optionally filter the logs by specifying the `--earliest` and `--latest` parameters with epoch seconds values. This allows you to collect logs within a specific time range.

> [!NOTE]
> The API doesn't (appear to) support filtering by date natively, so the script will retrieve all logs and filter them client-side based on the provided date range. On large datasets, this may result in longer execution times.

### Examples
To collect DLP logs for the enterprise domain `example-enterprise.slack.com` using a `d` cookie stored in the environment variable `D_COOKIE`, run:
```bash
python slack_dlp_log_extractor.py --enterprise-domain example-enterprise.slack.com --slack-cookie $D_COOKIE
```

To collect DLP logs for a specific date range, run:
```bash
python slack_dlp_log_extractor.py --enterprise-domain example-enterprise.slack.com --slack-cookie $D_COOKIE --earliest 1767268800 --latest 1767279600
```

