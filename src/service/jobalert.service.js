import { db } from '../database/index.database.js'
function checkData(data, errorMessage) {
    if (!data || data.length === 0) {
        throw new Error(errorMessage)
    }
}
export const getAllJobAlertsService = async ({ skip, limit }) => {
    try {
        const data = await db
            .select('*')
            .from('jobalert')
            .offset(skip)
            .limit(limit)
        checkData(data, 'Jobalert not found')
        return data
    } catch (error) {
        throw new Error(error.message)
    }
}
export const getJobAlertByIdService = async (id) => {
    try {
        const data = await db.select('*').from('jobalert').where('id', id)
        checkData(data[0], 'Jobalert not found')
        return data[0]
    } catch (error) {
        throw new Error(error.message)
    }
}
export const createJobAlertService = async (body) => {
    try {
        const data = await db('jobalert')
            .insert({ ...body })
            .returning('*')
        checkData(data[0], 'Jobalert not created')
        return data[0]
    } catch (error) {
        throw new Error(error.message)
    }
}
export const updateJobAlertService = async (id, body) => {
    try {
        const data = await db('jobalert')
            .where('id', id)
            .update({ ...body })
            .returning('*')
        checkData(data[0], 'Jobalert not updated')
        return data[0]
    } catch (error) {
        throw new Error(error.message)
    }
}
export const deleteJobAlertService = async (id) => {
    try {
        const data = await db('jobalert').where('id', id).del().returning('*')
        checkData(data[0], 'Jobalert not deleted')
        return data[0]
    } catch (error) {
        throw new Error(error.message)
    }
}
export const getStatisticsService = async (userId) => {
    try {
        const jobs = await db('jobalert').select('*').where('user_id', userId)
        if (jobs.length < 1) {
            throw new Error('You have not got work')
        }
        const jobsId = []
        const allJobs = []
        for (const obj of jobs) {
            jobsId.push(obj.job_id)
        }
        for (const id of jobsId) {
            const job = await db('joblisting').select('*').where('id', id)
            allJobs.push(job)
        }
        return { success: true, allJobs }
    } catch (error) {
        return { success: false, error }
    }
}
export const getStatisticsByJobIdService = async (jobId) => {
    try {
        const jobs = await db('jobalert').select('*').where('job_id', jobId)
        const num = jobs.length
        return { success: true, num }
    } catch (error) {
        return { success: false, error }
    }
}
