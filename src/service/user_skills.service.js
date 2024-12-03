import { db } from '../database/knex.js'

export const createUserSkillService = async (user_id, skill_id) => {
    try {
        const [user] = await db('users').select('*').where('id', '=', user_id)
        const [skill] = await db('skills')
            .select('*')
            .where('id', '=', skill_id)

        if (!user) {
            throw new Error('User not found')
        }
        if (!skill) {
            throw new Error('Skill not found')
        }

        await db('user_skills').insert({ user_id, skill_id })
        return { success: true }
    } catch (error) {
        return { success: false, error }
    }
}

export const getAllUserSkillsService = async ({ limit, skip }) => {
    try {
        const userSkills = await db('user_skills')
            .select('*')
            .offset(skip)
            .limit(limit)
        if (!userSkills.length) {
            throw new Error('No user skills found')
        }
        return { success: true, userSkills }
    } catch (error) {
        return { success: false, error }
    }
}

export const getUserSkillService = async (userId, skillId) => {
    try {
        const [userSkill] = await db('user_skills')
            .where({ user_id: userId, skill_id: skillId })
            .select('*')

        if (!userSkill) {
            throw new Error('User skill not found')
        }
        return { success: true, userSkill }
    } catch (error) {
        return { success: false, error }
    }
}

export const updateUserSkillService = async (userId, skillId, updates) => {
    try {
        const updated = await db('user_skills')
            .where({ user_id: userId, skill_id: skillId })
            .update(updates)

        if (!updated) {
            throw new Error('User skill not found')
        }
        return { success: true }
    } catch (error) {
        return { success: false, error }
    }
}

export const deleteUserSkillService = async (userId, skillId) => {
    try {
        const deleted = await db('user_skills')
            .where({ user_id: userId, skill_id: skillId })
            .del()

        if (!deleted) {
            throw new Error('User skill not found')
        }
        return { success: true }
    } catch (error) {
        return { success: false, error }
    }
}
