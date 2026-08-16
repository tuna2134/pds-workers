import journal from "../../drizzle/repo/meta/_journal.json";
import migration0 from "../../drizzle/repo/0000_small_stardust.sql";
import migration1 from "../../drizzle/repo/0001_many_alex_power.sql";
import migration2 from "../../drizzle/repo/0002_nifty_fenris.sql";

export default { journal, migrations: { m0000: migration0, m0001: migration1, m0002: migration2 } };
