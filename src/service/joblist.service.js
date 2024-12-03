import { db } from '../database/index.database.js'
import { sendMail } from '../helpers/sendEmail.js'
function checkData(data, errorMessage) {
    if (!data || data.length === 0) {
        throw new Error(errorMessage)
    }
}
export const getAllJoblistsService = async ({ skip, limit }) => {
    try {
        const data = await db
            .select('*')
            .from('joblisting')
            .offset(skip)
            .limit(limit)
        checkData(data, 'Joblists not found')
        return data
    } catch (error) {
        throw new Error(error.message)
    }
}
export const getJoblistByIdService = async (id) => {
    try {
        const data = await db.select('*').from('joblisting').where('id', id)
        checkData(data[0], 'Joblist not found')
        return data[0]
    } catch (error) {
        throw new Error(error.message)
    }
}
export const serachJobListService = async (query) => {
    try {
        const { title } = query
        const jobList = await db('joblisting')
            .select('*')
            .where('title', 'ILIKE', `%${title}%`)
        return { success: true, jobList }
    } catch (error) {
        return { success: false, error }
    }
}
export const createJoblistService = async (body) => {
    try {
        const data = await db('joblisting')
            .insert({
                ...body,
            })
            .returning('*')

        checkData(data[0], 'Joblist not created')
        await sendNotification(data[0])
        return data[0]
    } catch (error) {
        throw new Error(`Failed to create joblist: ${error.message}`)
    }
}
export const updateJoblistService = async (id, body) => {
    try {
        const data = await db('joblisting')
            .update({
                ...body,
                requirements: JSON.stringify(body.requirements),
                salaryRange: JSON.stringify(body.salaryRange),
            })
            .where('id', id)
            .returning('*')
        checkData(data[0], 'Joblist not updated')
        return data[0]
    } catch (error) {
        throw new Error(error.message)
    }
}
export const deleteJoblistService = async (id) => {
    try {
        const data = await db('joblisting').where('id', id).del().returning('*')
        checkData(data[0], 'Joblist not deleted')
        return data[0]
    } catch (error) {
        throw new Error(error.message)
    }
}
export const getJobListsByCategoryService = async (categoryId) => {
    try {
        const category = await db('categories')
            .select('*')
            .where('id', categoryId)
        if (category.length < 1) {
            throw new Error('Category not found')
        }
        const jobs = await db('joblisting')
            .select('*')
            .where('category_id', categoryId)
        if (jobs.length < 1) {
            throw new Error('Jobs in this category not found')
        }
        return { success: true, jobs }
    } catch (error) {
        return { success: false, error }
    }
}
const sendNotification = async (joblist) => {
    try {
        const usersId = await db('wishlist as w')
            .select('w.user_id')
            .join('joblisting as j', 'w.company_id', 'j.company_id')
            .where('j.id', joblist.id)
        const emails = []
        for (const obj of usersId) {
            const userEmail = await db('users')
                .select('email')
                .where('id', obj.user_id)
            emails.push(userEmail[0].email)
        }
        for (const email of emails) {
            await sendMail(
                email,
                `Hello, we recommend this job to you`,
                `<h1>${JSON.stringify(joblist)}</h1>`,
            )
        }
    } catch (error) {}
}
