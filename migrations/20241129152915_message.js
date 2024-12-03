/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
export async function up(knex) {
    await knex.schema.createTable('message', function (table) {
        table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'))
        table.uuid('sender_id').notNullable().references('id').inTable('users')
        table
            .uuid('receiver_id')
            .notNullable()
            .references('id')
            .inTable('users')
        table.text('message').notNullable()
    })
}

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
export async function down(knex) {
    await knex.schema.dropTable('message')
}
