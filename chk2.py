import turso_client as db
import datetime
# Simulate app queries for today
start = '2026-09-06T00:00:00.000Z'
end = '2026-09-06T23:59:59.999Z'
for vid, nm in [('77e9ddc8-bfcc-4eb6-9dec-56511ca855ad','RIX'),('b0995a21-4f3a-46c5-b212-7de4a4d7513b','BYK')]:
    rows = db.query('SELECT lat, lon FROM location_logs WHERE vehicle_id=? AND captured_at >= ? AND captured_at <= ? ORDER BY captured_at ASC LIMIT 2000', [vid, start, end])
    distinct = len(set((round(r[0],4), round(r[1],4)) for r in rows))
    print(nm, 'rows:', len(rows), 'distinct:', distinct, 'first:', rows[0] if rows else None, 'last:', rows[-1] if rows else None)
