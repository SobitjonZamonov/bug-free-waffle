import { z } from 'zod'
export const userSkillsScheme = z.object({
    user_id: z.string().uuid(),
    skill_id: z.string().uuid(),
})
