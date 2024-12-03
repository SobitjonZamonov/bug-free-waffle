import { z } from 'zod'
export const jobalertScheme = z.object({
    job_id: z.string().uuid(),
    user_id: z.string().uuid(),
})
