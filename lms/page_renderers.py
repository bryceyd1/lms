"""Custom page renderers for LMS app.

Handles rendering of profile pages.
"""

import mimetypes
import os

import frappe
from frappe.website.page_renderers.base_renderer import BaseRenderer
from werkzeug.wrappers import Response
from werkzeug.wsgi import wrap_file


class SCORMRenderer(BaseRenderer):
	def can_render(self):
		return "scorm/" in self.path

	def render(self):
		# SECURITY FIX: Add CSP and security headers
		response = self._get_scorm_response()
		
		if response:
			# Add Content Security Policy
			response.headers['Content-Security-Policy'] = (
			    "default-src 'self'; "
			    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
			    "style-src 'self' 'unsafe-inline' https:; "
			    "img-src 'self' data: blob: https:; "
			    "media-src 'self' data: blob: https:; "
			    "connect-src 'self' blob: https:; "
			    "font-src 'self' data: https:; "
			    "frame-src 'self' https:; "
			    "object-src 'none'; "
			    "base-uri 'self'; "
			    "form-action 'self'; "
			)
			
			# Additional security headers
			response.headers['X-Frame-Options'] = 'SAMEORIGIN'
			response.headers['X-Content-Type-Options'] = 'nosniff'
			response.headers['Referrer-Policy'] = 'no-referrer'
			response.headers['X-XSS-Protection'] = '1; mode=block'
			
		return response

	def _get_scorm_response(self):
		# SECURITY FIX: Prevent path traversal attacks
		# Normalize and validate the path
		normalized_path = os.path.normpath(self.path.lstrip("/"))
		
		# Ensure path starts with scorm/ and doesn't escape
		if not normalized_path.startswith("scorm/"):
			frappe.throw("Invalid SCORM path", frappe.PermissionError)
			return None
		
		# Check for path traversal attempts
		if ".." in normalized_path or normalized_path.startswith("/"):
			frappe.throw("Path traversal detected", frappe.PermissionError)
			return None
		
		# Construct the full path
		site_public_path = frappe.local.site_path + "/public"
		full_path = os.path.join(site_public_path, normalized_path)
		
		# SECURITY FIX: Verify the resolved path is still within public/scorm
		real_path = os.path.realpath(full_path)
		allowed_base = os.path.realpath(os.path.join(site_public_path, "scorm"))
		
		if not real_path.startswith(allowed_base):
			frappe.throw("Access denied: Path outside allowed directory", frappe.PermissionError)
			return None

		extension = os.path.splitext(real_path)[1].lower()
		
		# SECURITY FIX: Whitelist allowed file extensions
		allowed_extensions = [
			'.html', '.htm', '.css', '.js', '.json',
			'.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp',
			'.mp4', '.webm', '.mp3', '.wav', '.ogg',
			'.pdf', '.txt', '.xml', '.woff', '.woff2', '.ttf', '.eot'
		]
		
		# Check if file has no extension (might be looking for index.html)
		if not extension:
			full_path = f"{full_path}.html"
			real_path = os.path.realpath(full_path)
			extension = '.html'
		
		# Block dangerous extensions
		if extension and extension not in allowed_extensions:
			frappe.throw(f"File type not allowed: {extension}", frappe.PermissionError)
			return None

		# Check if path exists and is actually a file
		if os.path.exists(real_path) and os.path.isfile(real_path):
			return self._create_response(real_path)
		
		# Check if it's a directory looking for index.html
		path_without_ext = full_path.replace(".html", "")
		if os.path.exists(path_without_ext) and os.path.isdir(path_without_ext):
			index_path = os.path.join(path_without_ext, "index.html")
			real_index_path = os.path.realpath(index_path)
			
			# Verify index.html is still in allowed directory
			if not real_index_path.startswith(allowed_base):
				return None
				
			if os.path.exists(real_index_path):
				return self._create_response(real_index_path)
		
		# SECURITY FIX: Rewrite file search with strict path validation
		elif not os.path.exists(real_path):
			# Only search within the specific chapter folder
			path_parts = normalized_path.split("/")
			if len(path_parts) >= 3:
				chapter_folder = "/".join(path_parts[:3])  # e.g., scorm/chapter-name/files
				chapter_folder_path = os.path.realpath(
					os.path.join(site_public_path, chapter_folder)
				)
				
				# Verify chapter folder is within allowed base
				if not chapter_folder_path.startswith(allowed_base):
					return None
				
				filename = os.path.basename(real_path)
				
				# SECURITY FIX: Limit search depth and validate found files
				correct_file_path = self._safe_file_search(
					chapter_folder_path, 
					filename, 
					allowed_base,
					allowed_extensions
				)
				
				if correct_file_path:
					return self._create_response(correct_file_path)
		
		return None

	def _safe_file_search(self, search_root, filename, allowed_base, allowed_extensions, max_depth=5):
		"""Safely search for a file within a directory with security checks."""
		# Validate search root is within allowed base
		if not os.path.realpath(search_root).startswith(allowed_base):
			return None
		
		current_depth = 0
		for root, _dirs, files in os.walk(search_root):
			# Limit search depth to prevent DOS
			depth = root[len(search_root):].count(os.sep)
			if depth > max_depth:
				continue
			
			if filename in files:
				file_path = os.path.join(root, filename)
				real_file_path = os.path.realpath(file_path)
				
				# Validate the found file is within allowed directory
				if not real_file_path.startswith(allowed_base):
					continue
				
				# Validate file extension
				extension = os.path.splitext(filename)[1].lower()
				if extension not in allowed_extensions:
					continue
				
				return real_file_path
		
		return None

	def _create_response(self, file_path):
		"""Create a Response object for the given file path."""
		try:
			# SECURITY FIX: Set proper MIME type, prevent MIME sniffing
			mimetype = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
			
			# SECURITY FIX: Prevent certain MIME types that could be dangerous
			dangerous_mimetypes = [
				'application/x-executable',
				'application/x-sharedlib',
				'application/x-sh',
				'text/x-python',
				'text/x-php'
			]
			
			if mimetype in dangerous_mimetypes:
				frappe.throw("File type not allowed", frappe.PermissionError)
				return None
			
			# Get file size
			file_size = os.path.getsize(file_path)
			
			# Check for Range header (required for Safari video playback)
			range_header = frappe.local.request.environ.get('HTTP_RANGE')
			
			if range_header:
				# Parse range header (format: "bytes=start-end")
				byte_range = range_header.replace('bytes=', '').split('-')
				start = int(byte_range[0]) if byte_range[0] else 0
				end = int(byte_range[1]) if len(byte_range) > 1 and byte_range[1] else file_size - 1
				length = end - start + 1
				
				# Open file and read the requested range
				with open(file_path, 'rb') as f:
					f.seek(start)
					data = f.read(length)
				
				# Create 206 Partial Content response
				response = Response(data, status=206, direct_passthrough=True)
				response.headers['Content-Range'] = f'bytes {start}-{end}/{file_size}'
				response.headers['Accept-Ranges'] = 'bytes'
				response.headers['Content-Length'] = str(length)
				response.mimetype = mimetype
				
				return response
			else:
				# Normal request without range - serve full file
				f = open(file_path, "rb")
				response = Response(
					wrap_file(frappe.local.request.environ, f), 
					direct_passthrough=True
				)
				response.headers['Accept-Ranges'] = 'bytes'  # Advertise Range support
				response.headers['Content-Length'] = str(file_size)
				response.mimetype = mimetype
				
				return response
			
		except Exception as e:
			frappe.log_error(f"Error serving SCORM file: {str(e)}")
			return None