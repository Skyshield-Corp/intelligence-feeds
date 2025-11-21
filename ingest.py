import requests
import os
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Directory to store blocklists
OUTPUT_DIR = 'blocklists'

# List of Blocklist Sources
SOURCES = [
    {"name": "Abuse.ch SSL IPBL", "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"},
    {"name": "AdAway Default Blocklist", "url": "https://adaway.org/hosts.txt"},
    {"name": "AdAway Hosts", "url": "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt"},
    {"name": "AdGuard DNS Domains", "url": "https://v.firebog.net/hosts/AdguardDNS.txt"},
    {"name": "AdGuard DNS Filter", "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"},
    {"name": "Alienvault Reputation Generic", "url": "http://reputation.alienvault.com/reputation.generic"},
    {"name": "AntiScam Squad - Pi-Hole Crypto", "url": "https://raw.githubusercontent.com/AntiScamSquad/blocklist/main/pihole-crypto.txt"},
    {"name": "anti-AD EasyList", "url": "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-easylist.txt"},
    {"name": "AnudeepND - Adservers", "url": "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt"},
    {"name": "AnudeepND - CoinMiner", "url": "https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt"},
    {"name": "AnudeepND - Facebook", "url": "https://raw.githubusercontent.com/anudeepND/blacklist/master/facebook.txt"},
    {"name": "Badd-Boyz Hosts", "url": "https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts"},
    {"name": "Bambenek DGA Feed High", "url": "http://osint.bambenekconsulting.com/feeds/dga-feed-high.csv"},
    {"name": "Banco do Brasil Malicious", "url": "https://raw.githubusercontent.com/marcosoliv/no-track/master/malware-banco-do-brasil.txt"},
    {"name": "Blocklist Project - Porn", "url": "https://blocklistproject.github.io/Lists/porn.txt"},
    {"name": "Blocklist Project - Ransomware", "url": "https://blocklistproject.github.io/Lists/ransomware.txt"},
    {"name": "Blocklist Project - Redirect", "url": "https://blocklistproject.github.io/Lists/redirect.txt"},
    {"name": "Blocklist Project - Scam", "url": "https://blocklistproject.github.io/Lists/scam.txt"},
    {"name": "Blocklist Project - TikTok", "url": "https://blocklistproject.github.io/Lists/tiktok.txt"},
    {"name": "Blocklist Project - Torrent", "url": "https://blocklistproject.github.io/Lists/torrent.txt"},
    {"name": "Blocklist Project - Tracking", "url": "https://blocklistproject.github.io/Lists/tracking.txt"},
    {"name": "Blocklist Project - Fraud", "url": "https://blocklistproject.github.io/Lists/fraud.txt"},
    {"name": "Blocklist Project - Phishing", "url": "https://blocklistproject.github.io/Lists/phishing.txt"},
    {"name": "Blocklist Project - Abuse", "url": "https://blocklistproject.github.io/Lists/abuse.txt"},
    {"name": "Blocklist Project - Ads", "url": "https://blocklistproject.github.io/Lists/ads.txt"},
    {"name": "Blocklist Project - Crypto", "url": "https://blocklistproject.github.io/Lists/crypto.txt"},
    {"name": "Blocklist Project - Drugs", "url": "https://blocklistproject.github.io/Lists/drugs.txt"},
    {"name": "Blocklist Project - Everything", "url": "https://blocklistproject.github.io/Lists/everything.txt"},
    {"name": "Blocklist Project - Facebook", "url": "https://blocklistproject.github.io/Lists/facebook.txt"},
    {"name": "Blocklist Project - Gambling", "url": "https://blocklistproject.github.io/Lists/gambling.txt"},
    {"name": "Blocklist Project - Malware", "url": "https://blocklistproject.github.io/Lists/malware.txt"},
    {"name": "Blocklist Project - Piracy", "url": "https://blocklistproject.github.io/Lists/piracy.txt"},
    {"name": "BarbBlock Hosts File", "url": "https://raw.githubusercontent.com/paulgb/BarbBlock/master/blacklists/hosts-file.txt"},
    {"name": "bitwire-it IP blocklist", "url": "https://bitwire.it/data/ip-blocklist"},
    {"name": "Blocklist - Apache attacks", "url": "https://lists.blocklist.de/lists/apache.txt"},
    {"name": "Blocklist - All Attacks", "url": "https://lists.blocklist.de/lists/all.txt"},
    {"name": "Blocklist - FTP attacks", "url": "https://lists.blocklist.de/lists/ftp.txt"},
    {"name": "Blocklist - IMAP attacks", "url": "https://lists.blocklist.de/lists/imap.txt"},
    {"name": "Blocklist - IRC bots", "url": "https://lists.blocklist.de/lists/bots.txt"},
    {"name": "Blocklist - Mail attacks", "url": "https://lists.blocklist.de/lists/mail.txt"},
    {"name": "Blocklist - SIP/VoIP", "url": "https://lists.blocklist.de/lists/sip.txt"},
    {"name": "Blocklist - SSH attacks", "url": "https://lists.blocklist.de/lists/ssh.txt"},
    {"name": "Blocklist - StrongIPs", "url": "https://lists.blocklist.de/lists/strongips.txt"},
    {"name": "Mandiant APT1 Report", "url": "https://raw.githubusercontent.com/aptnotes/data/master/APT1/APT1_Appendix_D.txt"},
]

def ingest_blocklists():
    """Downloads blocklists from configured sources."""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        logging.info(f"Created directory: {OUTPUT_DIR}")
    
    success_count = 0
    
    for source in SOURCES:
        safe_name = source['name'].replace(' ', '_').replace('/', '-').lower() + '.txt'
        file_path = os.path.join(OUTPUT_DIR, safe_name)
        
        try:
            logging.info(f"Fetching {source['name']}...")
            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; BlocklistIngestBot/1.0; +https://github.com/hrtywhy)'
            }
            response = requests.get(source['url'], headers=headers, timeout=30)
            response.raise_for_status()
            
            # Optional: Basic validation (check if content length > 0)
            if len(response.text.strip()) == 0:
                logging.warning(f"Empty response from {source['name']}, skipping.")
                continue
                
            with open(file_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(f"# Source: {source['name']}\n")
                f.write(f"# Updated: {datetime.utcnow().isoformat()}\n")
                f.write(f"# URL: {source['url']}\n\n")
                f.write(response.text)
            
            logging.info(f"Successfully saved to {file_path}")
            success_count += 1
            
        except Exception as e:
            logging.error(f"Failed to fetch {source['name']}: {str(e)}")

    logging.info(f"Ingestion complete. Successfully updated {success_count} out of {len(SOURCES)} lists.")

if __name__ == "__main__":
    ingest_blocklists()
