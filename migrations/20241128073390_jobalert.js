/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
export async function up(knex) {
    await knex.schema.createTable('jobalert', function (table) {
        table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'))
        table
            .uuid('job_id')
            .unsigned()
            .references('id')
            .inTable('joblisting')
            .onDelete(`CASCADE`)
            .onUpdate(`CASCADE`)
            .notNullable()
        table
            .uuid('user_id')
            .unsigned()
            .references('id')
            .inTable('users')
            .onDelete(`CASCADE`)
            .onUpdate(`CASCADE`)
            .notNullable()
        table.timestamps(true, true)
    })
}

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
export async function down(knex) {
    await knex.schema.dropTable('jobalert')
}
