#!/usr/bin/env python3
"""ShieldFlow Twitter Poster - Simple script to post tweets.

Usage:
    export TWITTER_API_KEY="your-api-key"
    export TWITTER_API_SECRET="your-api-secret"  
    export TWITTER_BEARER="your-bearer-token"
    python scripts/post_tweet.py "Your tweet text"
"""

import os
import sys

# Load credentials from environment variables
API_KEY = os.environ.get("TWITTER_API_KEY", "")
API_SECRET = os.environ.get("TWITTER_API_SECRET", "")
BEARER = os.environ.get("TWITTER_BEARER", "")

if not API_KEY or not API_SECRET or not BEARER:
    print("Error: Missing credentials.")
    print("Set environment variables:")
    print("  export TWITTER_API_KEY='your-api-key'")
    print("  export TWITTER_API_SECRET='your-api-secret'")
    print("  export TWITTER_BEARER='your-bearer-token'")
    sys.exit(1)

def post_tweet(text: str) -> dict:
    """Post a tweet using OAuth 1.0a."""
    try:
        import tweepy
    except ImportError:
        print("Error: tweepy not installed. Run: pip install tweepy")
        sys.exit(1)
    
    # Split API key (format: oauth_token-oauth_token_secret)
    parts = API_KEY.split('-', 1)
    oauth_token = parts[0]
    oauth_token_secret = parts[1] if len(parts) > 1 else ""
    
    # Create client and post
    client = tweepy.Client(
        bearer_token=BEARER,
        consumer_key=oauth_token,
        consumer_secret=API_SECRET,
        access_token=API_KEY,
        access_token_secret=oauth_token_secret + "-" + API_SECRET,
    )
    
    response = client.create_tweet(text=text)
    return response.data

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/post_tweet.py \"Your tweet text\"")
        sys.exit(1)
    
    tweet_text = " ".join(sys.argv[1:])
    print(f"Posting: {tweet_text}")
    
    try:
        result = post_tweet(tweet_text)
        print(f"✅ Posted! ID: {result['id']}")
    except Exception as e:
        print(f"❌ Error: {e}")
