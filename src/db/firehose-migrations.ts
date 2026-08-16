import journal from "../../drizzle/firehose/meta/_journal.json";
import migration0 from "../../drizzle/firehose/0000_cheerful_alex_wilder.sql";

export default { journal, migrations: { m0000: migration0 } };
