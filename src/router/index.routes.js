import { Router } from 'express'
import {
    applicationRouter,
    authRouter,
    categoryRouter,
    companyRouter,
    jobalertRouter,
    joblistRouter,
    messageRouter,
    reviewRouter,
    skillsRouter,
    userRouter,
    userSkillsRouter,
    wishlistRouter,
} from './routes.js'

export const router = Router()

router.use('/auth', authRouter)
router.use('/user', userRouter)
router.use('/message', messageRouter)
router.use('/company', companyRouter)
router.use('/review', reviewRouter)
router.use('/categories', categoryRouter)
router.use('/jobs', joblistRouter)
router.use('/jobalert', jobalertRouter)
router.use('/application', applicationRouter)
router.use('/skills', skillsRouter)
router.use('/user_skills', userSkillsRouter)
router.use('/wishlist', wishlistRouter)
