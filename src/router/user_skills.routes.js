import { Router } from 'express'
import {
    createUserSkill,
    deleteUserSkill,
    getAllUserSkills,
    getUserSkill,
    updateUserSkill,
} from '../controller/index.controller.js'
import {
    checkToken,
    pagination,
    validationMiddleware,
} from '../middleware/index.middleware.js'
import { userSkillsScheme } from '../validations/user_skills.schema.js'

export const userSkillsRouter = Router()

userSkillsRouter.post(
    '/skill',
    checkToken,
    validationMiddleware(userSkillsScheme),
    createUserSkill,
)
userSkillsRouter.get('/', checkToken, pagination, getAllUserSkills)
userSkillsRouter.get('/:id', checkToken, getUserSkill)
userSkillsRouter.put('/:id', checkToken, updateUserSkill)
userSkillsRouter.delete('/:id', checkToken, deleteUserSkill)
