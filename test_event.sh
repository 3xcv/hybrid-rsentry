#!/bin/bash
# Sends a test CANARY_TOUCHED event to trigger the full pipeline:
# CRITICAL alert → auto-containment → AI analysis

curl -X POST http://localhost:8000/api/events \
  -H "Content-Type: application/json" \
  -d '{"host_id":"ATOMIC","timestamp":"2026-05-26T00:00:00Z","event_type":"CANARY_TOUCHED","severity":"CRITICAL","pid":0,"process_name":"test","file_path":"/home/mohammad/Documents/AAA_000.txt","entropy_delta":0,"lineage_score":0,"canary_hit":true,"details":{}}'

echo ""
echo "Done. Check http://localhost:3000 for the CRITICAL alert."
