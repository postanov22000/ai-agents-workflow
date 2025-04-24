if os.getenv("GITHUB_ACTIONS") == "true":
    respond_to_emails()  # Run once
else:
    while True:  # Local testing
        respond_to_emails()
        time.sleep(300)
