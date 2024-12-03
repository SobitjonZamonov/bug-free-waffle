import { Router } from 'express'
import {
    createSkill,
    deleteSkill,
    getAllSkills,
    getSkill,
    updateSkill,
} from '../controller/index.controller.js'
import {
    checkToken,
    pagination,
    roleGuard,
    validationMiddleware,
} from '../middleware/index.middleware.js'
import { skillsScheme } from '../validations/skills.schema.js'

export const skillsRouter = Router()

skillsRouter.post(
    '/skill',
    checkToken,
    validationMiddleware(skillsScheme),
    roleGuard('admin'),
    createSkill,
)
skillsRouter.get('/', checkToken, roleGuard('admin'), pagination, getAllSkills)
skillsRouter.get('/:id', checkToken, roleGuard('admin'), getSkill)
skillsRouter.put('/:id', checkToken, roleGuard('admin'), updateSkill)
skillsRouter.delete('/:id', checkToken, roleGuard('admin'), deleteSkill)
