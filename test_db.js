const db = require('./src/db.js');

async function test() {
    await db.initDb();
    const result = db.getServers({});
    console.log(result.servers.length);
}

test().catch(console.error);
