import { db } from '../database/knex.js'

export const createSkillService = async ({ name, category_id }) => {
    try {
        const category = await db('categories').where('id', category_id).first()
        if (!category) {
            throw new Error('Category not found')
        }

        await db('skills').insert({ name, category_id })
        return { success: true }
    } catch (error) {
        return { success: false, error }
    }
}

export const getAllSkillsService = async ({ skip, limit }) => {
    try {
        const skills = await db('skills').select('*').offset(skip).limit(limit)
        if (skills.length === 0) {
            throw new Error('No skills found')
        }

        return { success: true, skills }
    } catch (error) {
        return { success: false, error }
    }
}

export const getSkillService = async (skillId) => {
    try {
        const skill = await db('skills').where('id', skillId).first()
        if (!skill) {
            throw new Error('Skill not found')
        }

        return { success: true, skill }
    } catch (error) {
        return { success: false, error }
    }
}

export const updateSkillService = async (skillId, { name, category_id }) => {
    try {
        const category = await db('categories').where('id', category_id).first()
        if (!category) {
            throw new Error('Category not found')
        }

        const updatedSkill = await db('skills')
            .where('id', skillId)
            .update({ name, category_id })
            .returning('*')

        if (updatedSkill.length === 0) {
            throw new Error('Skill not found')
        }

        return { success: true, updatedSkill: updatedSkill[0] }
    } catch (error) {
        return { success: false, error }
    }
}

export const deleteSkillService = async (skillId) => {
    try {
        const deletedRows = await db('skills').where('id', skillId).del()

        if (deletedRows === 0) {
            throw new Error('Skill not found')
        }

        return { success: true }
    } catch (error) {
        return { success: false, error }
    }
}
