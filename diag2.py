import turso_client as db
print('=== vehicle_events (last 15) ===')
for r in db.query('SELECT vehicle_id, event_type, event_data, created_at FROM vehicle_events ORDER BY created_at DESC LIMIT 15'):
    d = (r[2] or '')[:50]
    print('  %s | %s | %s | %s' % (r[0][:8], r[1], d, r[3]))
print()
print('=== distinct locations today ===')
for vid, nm in [('77e9ddc8-bfcc-4eb6-9dec-56511ca855ad','RIX'),('b0995a21-4f3a-46c5-b212-7de4a4d7513b','BYK')]:
    rows = db.query("SELECT lat, lon, COUNT(*) c FROM location_logs WHERE vehicle_id='" + vid + "' AND captured_at >= '2026-09-06T00:00:00.000Z' GROUP BY lat, lon ORDER BY c DESC LIMIT 3")
    print(nm, ':')
    for r in rows: print('  %.6f %.6f x%d' % (r[0], r[1], r[2]))
print()
print('=== vehicles ===')
for r in db.query('SELECT id, name, status, last_fix_at, last_lat, last_lon FROM vehicles'):
    print('  %s | %s | %s | %s | %.6f %.6f' % (r[0][:8], r[1], r[2], r[3], r[4], r[5]))
