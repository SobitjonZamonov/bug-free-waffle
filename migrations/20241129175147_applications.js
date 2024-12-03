/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
export async function up(knex) {
    await knex.schema.createTable('application', function (table) {
        table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'))
        table
            .uuid('user_id')
            .notNullable()
            .references('id')
            .inTable('users')
            .onDelete('CASCADE')
            .onUpdate('CASCADE')
        table
            .uuid('job_id')
            .notNullable()
            .references('id')
            .inTable('joblisting')
            .onDelete('CASCADE')
            .onUpdate('CASCADE')
        table.string('resume_url').notNullable()
        table.text('cover_letter').notNullable()
        table
            .enu('status', [
                'submitted',
                'reviewed',
                'interviewing',
                'hired',
                'rejected',
            ])
            .notNullable()
        table.timestamps(true, true)
    })
}
/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
export async function down(knex) {
    await knex.schema.dropTable('application')
}
