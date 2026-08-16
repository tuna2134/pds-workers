import { drizzle } from "drizzle-orm/d1";
import * as schema from "./schema/d1";
export const d1 = (database: D1Database) => drizzle(database, { schema });
