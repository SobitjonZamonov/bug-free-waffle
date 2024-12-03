import {
    createSkillService,
    getAllSkillsService,
    getSkillService,
    updateSkillService,
    deleteSkillService,
} from '../service/index.service.js'
import { statusCode } from '../utils/statuscodes.js'

export const createSkill = async (req, res, next) => {
    try {
        const { name, category_id } = req.body
        const { success, error } = await createSkillService({
            name,
            category_id,
        })

        if (success) {
            return res.status(statusCode.CREATED).send({
                message: 'Skill created successfully',
            })
        }

        return res.status(statusCode.BAD_REQUEST).send({
            message: 'Failed to create skill',
            error: error.message,
        })
    } catch (error) {
        next(error)
    }
}

export const getAllSkills = async (req, res, next) => {
    try {
        const { success, error, skills } = await getAllSkillsService(
            req.pagination,
        )

        if (success) {
            return res.status(statusCode.OK).send({
                message: 'Success',
                skills,
            })
        }

        return res.status(statusCode.NOT_FOUND).send({
            message: 'Skills not found',
            error: error.message,
        })
    } catch (error) {
        next(error)
    }
}

export const getSkill = async (req, res, next) => {
    try {
        const { success, error, skill } = await getSkillService(req.params.id)

        if (success) {
            return res.status(statusCode.OK).send({
                message: 'Success',
                skill,
            })
        }

        return res.status(statusCode.NOT_FOUND).send({
            message: 'Skill not found',
            error: error.message,
        })
    } catch (error) {
        next(error)
    }
}

export const updateSkill = async (req, res, next) => {
    try {
        const { name, category_id } = req.body
        const { success, error, updatedSkill } = await updateSkillService(
            req.params.id,
            { name, category_id },
        )

        if (success) {
            return res.status(statusCode.OK).send({
                message: 'Skill updated successfully',
                updatedSkill,
            })
        }

        return res.status(statusCode.BAD_REQUEST).send({
            message: 'Failed to update skill',
            error: error.message,
        })
    } catch (error) {
        next(error)
    }
}

export const deleteSkill = async (req, res, next) => {
    try {
        const { success, error } = await deleteSkillService(req.params.id)

        if (success) {
            return res.status(statusCode.OK).send({
                message: 'Skill deleted successfully',
            })
        }

        return res.status(statusCode.INTERNAL_SERVER_ERROR).send({
            message: 'Failed to delete skill',
            error: error.message,
        })
    } catch (error) {
        next(error)
    }
}
