import fetch, { Response } from 'node-fetch';
import { USER_AGENT } from '../runtime/constants.js';
import { wikiService } from './wikiService.js';
import { getMwn, clearMwnCache } from './mwn.js';

type RequestConfig = {
	headers: Record<string, string>;
	body: Record<string, unknown> | undefined;
};

class HttpError extends Error {
	status: number;
	constructor( message: string, status: number ) {
		super( message );
		this.name = 'HttpError';
		this.status = status;
	}
}

// MediaWiki session cookies from a bot-password login can silently expire on the
// cached mwn instance. When that happens, cookie-based REST calls fail with 401/403
// while action-API calls still recover via mwn's own retry. On first auth failure
// we drop the cached mwn (forcing a re-login) and retry the REST call once.
async function retryOnAuthFailure<T>(
	op: () => Promise<T>,
	needAuth: boolean
): Promise<T> {
	try {
		return await op();
	} catch ( err ) {
		if ( !( err instanceof HttpError ) || ( err.status !== 401 && err.status !== 403 ) ) {
			throw err;
		}
		const { private: privateWiki, token } = wikiService.getCurrent().config;
		// Static OAuth2 tokens or fully-public wikis won't benefit from re-login.
		if ( token || ( !needAuth && !privateWiki ) ) {
			throw err;
		}
		clearMwnCache();
		return await op();
	}
}

async function withAuth(
	headers: Record<string, string>,
	body: Record<string, unknown> | undefined,
	needAuth: boolean
): Promise<RequestConfig> {
	const { private: privateWiki, token } = wikiService.getCurrent().config;

	if ( !needAuth && !privateWiki ) {
		return { headers, body };
	}

	if ( token !== undefined && token !== null ) {
		// OAuth2 authentication - just add Bearer token
		return {
			headers: { ...headers, Authorization: `Bearer ${ token }` },
			body
		};
	}

	// Cookie-based authentication - add cookies and CSRF token
	const cookies = await getCookiesFromJar();
	if ( cookies === undefined ) {
		return { headers, body };
	}

	return {
		headers: { ...headers, Cookie: cookies },
		body: body ? { ...body, token: await getCsrfToken() } : body
	};
}

async function getCsrfToken(): Promise<string> {
	const mwn = await getMwn();
	return await mwn.getCsrfToken();
}

async function getCookiesFromJar(): Promise<string | undefined> {
	const mwn = await getMwn();
	const cookieJar = mwn.cookieJar;
	if ( !cookieJar ) {
		return undefined;
	}

	const { server, scriptpath } = wikiService.getCurrent().config;

	// Get cookies for the REST API URL
	const restApiUrl = `${ server }${ scriptpath }/rest.php`;
	const cookies = cookieJar.getCookieStringSync( restApiUrl );

	if ( cookies ) {
		return cookies;
	}

	// Fallback: try getting cookies for the domain
	return cookieJar.getCookieStringSync( server ) || undefined;
}

async function fetchCore(
	baseUrl: string,
	options?: {
		params?: Record<string, string>;
		headers?: Record<string, string>;
		body?: Record<string, unknown>;
		method?: string;
	}
): Promise<Response> {
	let url = baseUrl;

	if ( url.startsWith( '//' ) ) {
		url = 'https:' + url;
	}

	if ( options?.params ) {
		const queryString = new URLSearchParams( options.params ).toString();
		if ( queryString ) {
			url = `${ url }?${ queryString }`;
		}
	}

	const requestHeaders: Record<string, string> = {
		'User-Agent': USER_AGENT
	};

	if ( options?.headers ) {
		Object.assign( requestHeaders, options.headers );
	}

	const fetchOptions: { headers: Record<string, string>; method?: string; body?: string } = {
		headers: requestHeaders,
		method: options?.method || 'GET'
	};
	if ( options?.body ) {
		fetchOptions.body = JSON.stringify( options.body );
	}
	const response = await fetch( url, fetchOptions );
	if ( !response.ok ) {
		const errorBody = await response.text().catch( () => 'Could not read error response body' );
		throw new HttpError(
			`HTTP error! status: ${ response.status } for URL: ${ response.url }. Response: ${ errorBody }`,
			response.status
		);
	}
	return response;
}

export async function makeApiRequest<T>(
	url: string,
	params?: Record<string, string>
): Promise<T> {
	const response = await fetchCore( url, {
		params,
		headers: { Accept: 'application/json' }
	} );
	return ( await response.json() ) as T;
}

export async function makeRestGetRequest<T>(
	path: string,
	params?: Record<string, string>,
	needAuth: boolean = false
): Promise<T> {
	return retryOnAuthFailure( async () => {
		const headers: Record<string, string> = {
			Accept: 'application/json'
		};

		const { headers: authHeaders } = await withAuth(
			headers,
			undefined,
			needAuth
		);

		const { server, scriptpath } = wikiService.getCurrent().config;

		const response = await fetchCore( `${ server }${ scriptpath }/rest.php${ path }`, {
			params,
			headers: authHeaders
		} );
		return ( await response.json() ) as T;
	}, needAuth );
}

export async function makeRestPutRequest<T>(
	path: string,
	body: Record<string, unknown>,
	needAuth: boolean = false
): Promise<T> {
	return retryOnAuthFailure( async () => {
		const headers: Record<string, string> = {
			Accept: 'application/json',
			'Content-Type': 'application/json'
		};

		const { headers: authHeaders, body: authBody } = await withAuth(
			headers,
			body,
			needAuth
		);

		const { server, scriptpath } = wikiService.getCurrent().config;

		const response = await fetchCore( `${ server }${ scriptpath }/rest.php${ path }`, {
			headers: authHeaders,
			method: 'PUT',
			body: authBody
		} );
		return ( await response.json() ) as T;
	}, needAuth );
}

export async function makeRestPostRequest<T>(
	path: string,
	body?: Record<string, unknown>,
	needAuth: boolean = false
): Promise<T> {
	return retryOnAuthFailure( async () => {
		const headers: Record<string, string> = {
			Accept: 'application/json',
			'Content-Type': 'application/json'
		};

		const { headers: authHeaders, body: authBody } = await withAuth(
			headers,
			body,
			needAuth
		);

		const { server, scriptpath } = wikiService.getCurrent().config;

		const response = await fetchCore( `${ server }${ scriptpath }/rest.php${ path }`, {
			headers: authHeaders,
			method: 'POST',
			body: authBody
		} );
		return ( await response.json() ) as T;
	}, needAuth );
}

export async function fetchPageHtml( url: string ): Promise<string | null> {
	try {
		const response = await fetchCore( url );
		return await response.text();
	} catch {
		return null;
	}
}

export async function fetchImageAsBase64( url: string ): Promise<string | null> {
	try {
		const response = await fetchCore( url );
		const arrayBuffer = await response.arrayBuffer();
		const buffer = Buffer.from( arrayBuffer );
		return buffer.toString( 'base64' );
	} catch {
		return null;
	}
}

export function getPageUrl( title: string ): string {
	const { server, articlepath } = wikiService.getCurrent().config;
	return `${ server }${ articlepath }/${ encodeURIComponent( title ) }`;
}

export function formatEditComment( tool: string, comment?: string ): string {
	const suffix = `(via ${ tool } on MediaWiki MCP Server)`;
	if ( !comment ) {
		return `Automated edit ${ suffix }`;
	}
	return `${ comment } ${ suffix }`;
}
