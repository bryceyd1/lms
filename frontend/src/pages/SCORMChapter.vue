<template>
	<header
		class="sticky top-0 z-10 flex items-center justify-between border-b bg-surface-white px-3 py-2.5 sm:px-5"
	>
		<Breadcrumbs class="h-7" :items="breadcrumbs" />
	</header>
	<div
		v-if="
			readyToRender &&
			(enrollment.data?.length ||
				user.data?.is_moderator ||
				user.data?.is_instructor)
		"
	>
		<!-- SECURITY FIX: Add sandbox attribute to iframe -->
		<iframe
			:src="chapter.doc.launch_file"
			class="w-full h-[calc(100vh-3.00rem)]"
			sandbox="allow-scripts allow-same-origin"
			referrerpolicy="no-referrer"
			loading="lazy"
		/>
	</div>
	<div v-else-if="!enrollment.data?.length">
		<div class="text-center pt-10 px-5 md:px-0 pb-10">
			<div class="text-center">
				<div class="mb-4">
					{{
						__(
							'You are not enrolled in this course. Please enroll to access this lesson.'
						)
					}}
				</div>
				<Button variant="solid" @click="enrollStudent()">
					{{ __('Start Learning') }}
				</Button>
			</div>
		</div>
	</div>
</template>
<script setup>
import {
	Breadcrumbs,
	Button,
	call,
	createDocumentResource,
	createListResource,
	createResource,
	usePageMeta,
} from 'frappe-ui'
import { computed, inject, onBeforeMount, ref } from 'vue'
import { useSidebar } from '@/stores/sidebar'
import { sessionStore } from '../stores/session'

const { brand } = sessionStore()
const sidebarStore = useSidebar()
const user = inject('$user')
const readyToRender = ref(false)
const isSuccessfullyCompleted = ref(false)

const courseRestartOnFailure = false

const props = defineProps({
	courseName: {
		type: String,
		required: true,
	},
	chapterName: {
		type: String,
		required: true,
	},
})

onBeforeMount(() => {
	sidebarStore.isSidebarCollapsed = true
	setupSCORMAPI()
})

// SECURITY FIX: Add input sanitization function
const sanitizeInput = (value) => {
	if (typeof value !== 'string') return value
	
	// Remove HTML tags
	let clean = value.replace(/<[^>]*>/g, '')
	
	// Remove script event handlers
	clean = clean.replace(/on\w+\s*=/gi, '')
	
	// Remove javascript: pseudo-protocol
	clean = clean.replace(/javascript:/gi, '')
	
	// Encode special characters
	clean = clean
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#x27;')
	
	// Limit length to prevent DOS
	if (clean.length > 50000) {
		clean = clean.substring(0, 50000)
	}
	
	return clean
}

// SECURITY FIX: Validate keys against whitelist
const isValidSCORMKey = (key) => {
	const validKeys = [
		'cmi.core.lesson_status',
		'cmi.core.lesson_mode',      // ADD THIS - needed for initialization
		'cmi.core.exit',              // ADD THIS - needed for initialization
		'cmi.launch_data',
		'cmi.suspend_data',
		'cmi.core.score.raw',
		'cmi.score.raw',
		'cmi.core.lesson_location',
		'cmi.core.session_time',
		'cmi.interactions._count',
		'cmi.objectives._count'
	]
	
	// Allow keys with array indices like cmi.interactions.0.id
	const keyPattern = /^cmi\.(core\.)?(lesson_status|lesson_mode|exit|launch_data|suspend_data|score\.raw|lesson_location|session_time|interactions\.\d+\.\w+|objectives\.\d+\.\w+)$/
	
	return validKeys.includes(key) || keyPattern.test(key)
}

const chapter = createDocumentResource({
	doctype: 'Course Chapter',
	name: props.chapterName,
	auto: true,
	cache: ['chapter', props.chapterName],
	onSuccess(data) {
		progress.submit()
	},
})

const enrollment = createListResource({
	doctype: 'LMS Enrollment',
	fields: ['member', 'course'],
	filters: {
		course: props.courseName,
		member: user.data?.name,
	},
	auto: true,
	cache: ['enrollments', props.courseName, user.data?.name],
})

const getDataFromLMS = (key) => {
	if (!isValidSCORMKey(key)) {
		console.warn(`Invalid SCORM key attempted: ${key}`)
		return ''
	}
	
	if (key === 'cmi.core.lesson_status') {
		return progress.data?.status === 'Complete' ? 'passed' : 'incomplete'
	} else if (key === 'cmi.core.lesson_mode') {
		return 'normal'
	} else if (key === 'cmi.launch_data') {
		return sanitizeInput(progress.data?.scorm_content || '')
	} else if (key === 'cmi.suspend_data') {
		return sanitizeInput(progress.data?.scorm_content || '')
	} else if (key === 'cmi.core.score.raw') {
		return progress.data?.scorm_raw_score || ''
	}
	return ''
}

let saveTimeout = null
const debouncedSaveProgress = (scormDetails) => {
	clearTimeout(saveTimeout)
	saveTimeout = setTimeout(() => {
		saveProgress(scormDetails)
	}, 300)
}

// SECURITY FIX: Rate limiting for API calls
let apiCallCount = 0
let apiCallResetTime = Date.now()
const MAX_API_CALLS_PER_MINUTE = 1000

const checkRateLimit = () => {
	const now = Date.now()
	if (now - apiCallResetTime > 60000) {
		apiCallCount = 0
		apiCallResetTime = now
	}
	
	apiCallCount++
	if (apiCallCount > MAX_API_CALLS_PER_MINUTE) {
		console.error('SCORM API rate limit exceeded')
		return false
	}
	return true
}

const saveDataToLMS = (key, value) => {
	// SECURITY FIX: Validate key
	if (!isValidSCORMKey(key)) {
		console.warn(`Invalid SCORM key attempted: ${key}`)
		return
	}
	
	// SECURITY FIX: Check rate limit
	if (!checkRateLimit()) {
		return
	}
	
	// SECURITY FIX: Sanitize all input values
	const sanitizedValue = sanitizeInput(value)
	
	if (key === 'cmi.core.lesson_status') {
		
		if (value === 'passed') {
			isSuccessfullyCompleted.value = true
			saveProgress({
				is_complete: isSuccessfullyCompleted.value,
			})
		} else if (value === 'failed' && courseRestartOnFailure) {
			saveProgress({
				is_complete: isSuccessfullyCompleted.value,
			})
		}
	} else if (key === 'cmi.suspend_data') {
		debouncedSaveProgress({
			is_complete: isSuccessfullyCompleted.value,
			scorm_content: sanitizedValue,
		})
	} else if (key === 'cmi.score.raw' || key === 'cmi.core.score.raw') {
		// Validate score is numeric
		const score = parseFloat(value)
		if (isNaN(score) || score < 0 || score > 100) {
			console.warn(`Invalid score value: ${value}`)
			return
		}
		
		debouncedSaveProgress({
			is_complete: isSuccessfullyCompleted.value,
			scorm_raw_score: score,
		})
	}
}

const saveProgress = (scormDetails = null) => {
	call('lms.lms.doctype.course_lesson.course_lesson.save_progress', {
		lesson: chapter.doc.lessons[0].lesson,
		course: props.courseName,
		scorm_details: scormDetails,
	})
}

const progress = createResource({
	url: 'frappe.client.get_value',
	makeParams(values) {
		return {
			doctype: 'LMS Course Progress',
			fieldname: ['status', 'scorm_content', 'scorm_raw_score'],
			filters: {
				member: user.data?.name,
				lesson: chapter.doc.lessons[0].lesson,
				chapter: chapter.doc.name,
				course: chapter.doc?.course,
			},
		}
	},
	onSuccess(data) {
		readyToRender.value = true
	},
})

const enrollStudent = () => {
	enrollment.insert.submit(
		{
			course: props.courseName,
			member: user.data?.name,
		},
		{
			onSuccess(data) {
				window.location.reload()
			},
		}
	)
}

const setupSCORMAPI = () => {
	window.API_1484_11 = {
		Initialize: () => 'true',
		Terminate: () => 'true',
		GetValue: (key) => {
			console.log(`GET: ${key}`)
			return getDataFromLMS(key)
		},
		SetValue: (key, value) => {
			console.log(`SET: ${key} to value: ${value}`)
			saveDataToLMS(key, value)
			return 'true'
		},
		Commit: () => 'true',
		GetLastError: () => '0',
		GetErrorString: () => '',
		GetDiagnostic: () => '',
	}
	window.API = {
		LMSInitialize: () => 'true',
		LMSFinish: () => 'true',
		LMSGetValue: (key) => {
			console.log(`GET: ${key}`)
			return getDataFromLMS(key)
		},
		LMSSetValue: (key, value) => {
			console.log(`SET: ${key} to value: ${value}`)
			saveDataToLMS(key, value)
			return 'true'
		},
		LMSCommit: () => 'true',
		LMSGetLastError: () => '0',
		LMSGetErrorString: () => '',
		LMSGetDiagnostic: () => '',
	}
}

const breadcrumbs = computed(() => {
	return [
		{
			label: 'Courses',
			route: { name: 'Courses' },
		},
		{
			label: chapter.doc?.course_title,
			route: { name: 'CourseDetail', params: { courseName: props.courseName } },
		},
		{
			label: chapter.doc?.title,
		},
	]
})

usePageMeta(() => {
	return {
		title: chapter.doc?.title,
		icon: brand.favicon,
	}
})
</script>