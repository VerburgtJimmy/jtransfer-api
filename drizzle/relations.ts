import { relations } from "drizzle-orm/relations";
import { transfers, files } from "./schema";

export const filesRelations = relations(files, ({one}) => ({
	transfer: one(transfers, {
		fields: [files.transferId],
		references: [transfers.id]
	}),
}));

export const transfersRelations = relations(transfers, ({many}) => ({
	files: many(files),
}));