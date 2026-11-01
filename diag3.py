import turso_client as db
import datetime
start = '2026-09-06T00:00:00.000Z'
end = '2026-09-06T23:59:59.999Z'
for vid, nm in [('77e9ddc8-bfcc-4eb6-9dec-56511ca855ad','RIX'),('b0995a21-4f3a-46c5-b212-7de4a4d7513b','BYK')]:
    rows = db.query('SELECT COUNT(DISTINCT lat) FROM location_logs WHERE vehicle_id=\'' + vid + '\' AND captured_at >= \'' + start + '\'')
    print(nm, 'distinct lat values:', rows[0][0])
print()
print('=== getTodayDistance query (RIX) ===')
rows = db.query('SELECT lat, lon FROM location_logs WHERE vehicle_id=? AND captured_at >= ? AND captured_at <= ? ORDER BY captured_at ASC LIMIT 2000', ['77e9ddc8-bfcc-4eb6-9dec-56511ca855ad', start, end])
print('rows:', len(rows))
if rows:
    distinct = len(set((round(r[0],4), round(r[1],4)) for r in rows))
    print('distinct coords:', distinct)
    print('first:', rows[0], 'last:', rows[-1])
print()
print('=== getVehicleHistory query (BYK, today) ===')
rows = db.query('SELECT captured_at, lat, lon FROM location_logs WHERE vehicle_id=? AND captured_at >= ? AND captured_at < ? ORDER BY captured_at ASC LIMIT 2000', ['b0995a21-4f3a-46c5-b212-7de4a4d7513b', start, end])
print('rows:', len(rows))
distinct = len(set((round(r[1],4), round(r[2],4)) for r in rows))
print('distinct coords:', distinct)
print('first:', rows[0], 'last:', rows[-1])
