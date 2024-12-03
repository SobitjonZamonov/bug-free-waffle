import {
    createUserSkillService,
    getAllUserSkillsService,
    getUserSkillService,
    updateUserSkillService,
    deleteUserSkillService,
} from '../service/index.service.js'
import { statusCode } from '../utils/statuscodes.js'

export const createUserSkill = async (req, res, next) => {
    try {
        const { user_id, skill_id } = req.body
        const { success, error } = await createUserSkillService(
            user_id,
            skill_id,
        )

        if (success) {
            return res.status(statusCode.CREATED).send({
                message: 'User skill added successfully',
            })
        }
        return res.status(statusCode.BAD_REQUEST).send({
            message: 'Failed to add user skill',
            error: error.message,
        })
    } catch (error) {
        next(error)
    }
}

export const getAllUserSkills = async (req, res, next) => {
    try {
        const { success, error, userSkills } = await getAllUserSkillsService(
            req.pagination,
        )
        if (success) {
            return res.status(statusCode.OK).send({
                message: 'Success',
                userSkills,
            })
        }
        return res.status(statusCode.INTERNAL_SERVER_ERROR).send({
            message: 'Failed to fetch user skills',
            error: error.message,
        })
    } catch (error) {
        next(error)
    }
}

export const getUserSkill = async (req, res, next) => {
    try {
        const { userId, skillId } = req.params
        const { success, error, userSkill } = await getUserSkillService(
            userId,
            skillId,
        )

        if (success) {
            return res.status(statusCode.OK).send({
                message: 'Success',
                userSkill,
            })
        }
        return res.status(statusCode.NOT_FOUND).send({
            message: 'User skill not found',
            error: error.message,
        })
    } catch (error) {
        next(error)
    }
}

export const updateUserSkill = async (req, res, next) => {
    try {
        const { userId, skillId, level, priority } = req.body
        const { success, error } = await updateUserSkillService(
            userId,
            skillId,
            { level, priority },
        )

        if (success) {
            return res.status(statusCode.OK).send({
                message: 'User skill updated successfully',
            })
        }
        return res.status(statusCode.BAD_REQUEST).send({
            message: 'Failed to update user skill',
            error: error.message,
        })
    } catch (error) {
        next(error)
    }
}

export const deleteUserSkill = async (req, res, next) => {
    try {
        const { userId, skillId } = req.body
        const { success, error } = await deleteUserSkillService(userId, skillId)

        if (success) {
            return res.status(statusCode.OK).send({
                message: 'User skill removed successfully',
            })
        }
        return res.status(statusCode.BAD_REQUEST).send({
            message: 'Failed to remove user skill',
            error: error.message,
        })
    } catch (error) {
        next(error)
    }
}
