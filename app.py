"""
Flask web application for Security Assessor
"""
from flask import Flask, render_template, request, jsonify, redirect, url_for, Response, send_from_directory
from flask_cors import CORS
import json
import queue
import threading
import os
from datetime import datetime

from config import Config
from assessor import SecurityAssessor
from input_parser import InputParser
from data_sources import VirusTotalAPI

# Check if we're serving the built frontend or using templates
frontend_build_dir = os.path.join(os.path.dirname(__file__), 'frontend', 'dist')
use_react_frontend = os.path.exists(frontend_build_dir)

# Initialize Flask app
if use_react_frontend:
    # Serve the React build
    app = Flask(__name__, static_folder='frontend/dist', static_url_path='')
else:
    # Use traditional templates
    app = Flask(__name__)

CORS(app, resources={
    r"/api/*": {"origins": ["http://localhost:5173", "http://localhost:5000"]}
})
app.config.from_object(Config)

# Initialize assessor
try:
    assessor = SecurityAssessor(Config)
    
    # Initialize VirusTotal API if key is available
    virustotal_api = None
    if Config.VIRUSTOTAL_API_KEY:
        virustotal_api = VirusTotalAPI(Config.VIRUSTOTAL_API_KEY)
    
    # Initialize input parser with VirusTotal API
    input_parser = InputParser(virustotal_api=virustotal_api)

except Exception as e:
    assessor = None
    input_parser = InputParser()  # Fallback without VirusTotal

# Store progress queues for each assessment (keyed by session ID)
progress_queues = {}
# Store completed results (keyed by session ID)
completed_results = {}

@app.route('/')
def index():
    """Home page"""
    if use_react_frontend:
        return send_from_directory(app.static_folder, 'index.html')
    return render_template('index.html')

@app.route('/api/assess', methods=['POST'])
def assess():
    """Run security assessment"""
    
    if not assessor:
        return jsonify({
            'error': 'Assessment service is not available. Please check configuration.'
        }), 503
    
    try:
        # Get input
        data = request.get_json() if request.is_json else request.form
        input_text = data.get('input_text', '').strip()
        use_cache_raw = data.get('use_cache', True)
        # Handle both boolean and string values
        use_cache = use_cache_raw if isinstance(use_cache_raw, bool) else str(use_cache_raw).lower() == 'true'
        session_id = data.get('session_id', str(datetime.now().timestamp()))
        
        print(f"\n[REQUEST] input_text='{input_text}', use_cache={use_cache} (type: {type(use_cache_raw)})")
        
        if not input_text:
            return jsonify({'error': 'Please provide a product name, vendor, SHA1 hash, or URL'}), 400

        # Check if input is SHA1 - must have VirusTotal configured
        from input_parser import InputParser as StaticParser
        if StaticParser.is_sha1(input_text):
            if not virustotal_api:
                return jsonify({
                    'error': 'SHA1 hash detected but VirusTotal API is not configured. Please add VIRUSTOTAL_API_KEY to your .env file. Get a free API key at: https://www.virustotal.com/gui/join-us',
                    'input_type': 'sha1',
                    'sha1': input_text.strip().lower(),
                    'setup_required': True
                }), 400
        
        # Parse input to detect format (will perform VirusTotal lookup for SHA1)
        parsed = input_parser.parse_input(input_text)

        # For SHA1 hashes, VirusTotal lookup is MANDATORY
        if parsed['input_type'] == 'sha1':
            if not parsed.get('virustotal_data'):
                # This means VirusTotal lookup failed or hash not found
                return jsonify({
                    'error': f'SHA1 hash {parsed["sha1"][:8]}... not found in VirusTotal database. The file may not have been scanned yet. Please upload the file to VirusTotal first, or provide the product name directly.',
                    'input_type': 'sha1',
                    'sha1': parsed['sha1'],
                    'virustotal_url': f"https://www.virustotal.com/gui/file/{parsed['sha1']}",
                    'suggestion': 'Try uploading the file at https://www.virustotal.com/gui/home/upload'
                }), 404
            
            # VirusTotal data is available - proceed with assessment
            vt_data = parsed['virustotal_data']
            
            # Use product name from VirusTotal if available
            if parsed['product_name']:
                assessment_input = parsed['product_name']
            else:
                # Fall back to primary file name
                assessment_input = vt_data.get('primary_name', f"[SHA1: {parsed['sha1'][:8]}...]")

        # For vendor_product format, pass the product name only
        # The assessor will try to resolve the vendor internally via LLM
        if parsed['input_type'] == 'vendor_product':
            # Use product name for assessment, but log vendor for reference

            assessment_input = parsed['product_name']
        else:
            assessment_input = input_text
        
        # ============================================================
        # CHECK CACHE FIRST - Before spawning any threads or doing work
        # ============================================================
        if use_cache:
            print(f"\n[CACHE CHECK] Searching for: '{input_text}'")
            cached_result = assessor.cache.get_assessment_by_query(
                input_text,
                max_age_hours=Config.CACHE_EXPIRY_HOURS
            )
            
            if cached_result:
                print(f"[CACHE HIT] ✓ Found cached result for '{input_text}'")
                # Add input metadata to cached result
                cached_result['_input_metadata'] = {
                    'raw_input': input_text,
                    'parsed_type': parsed['input_type'],
                    'detected_vendor': parsed.get('vendor'),
                    'detected_product': parsed.get('product_name'),
                    'sha1': parsed.get('sha1'),
                    'virustotal_data': parsed.get('virustotal_data'),
                    '_from_cache': True
                }
                
                # Return cached result immediately without threading
                return jsonify({
                    'success': True,
                    'session_id': session_id,
                    'cached': True,
                    'assessment': cached_result
                })
            else:
                print(f"[CACHE MISS] ✗ No cached result for '{input_text}'")
        
        # Create progress queue for this session
        progress_queue = queue.Queue()
        progress_queues[session_id] = progress_queue
        
        # Define progress callback
        def progress_callback(progress_data):
            try:
                progress_queue.put(progress_data)
            except Exception as e:
                pass
        
        # Run assessment in background thread
        result_container = {}
        error_container = {}
        
        def run_assessment():
            try:
                result = assessor.assess_product(
                    assessment_input, 
                    use_cache=use_cache,
                    progress_callback=progress_callback,
                    virustotal_data=parsed.get('virustotal_data'),  # Pass VirusTotal data if available
                    search_term=input_text
                )
                
                # Add input metadata to result
                result['_input_metadata'] = {
                    'raw_input': input_text,
                    'parsed_type': parsed['input_type'],
                    'detected_vendor': parsed.get('vendor'),
                    'detected_product': parsed.get('product_name'),
                    'sha1': parsed.get('sha1'),
                    'virustotal_data': parsed.get('virustotal_data')
                }
                
                # Store result for later retrieval
                completed_results[session_id] = result
                
                # Signal completion with result
                progress_queue.put({
                    "stage": "complete", 
                    "status": "completed", 
                    "details": "Assessment finished",
                    "result": result
                })
            except Exception as e:
                error_container['error'] = str(e)
                progress_queue.put({"stage": "error", "status": "failed", "details": str(e)})
        
        assessment_thread = threading.Thread(target=run_assessment)
        assessment_thread.start()
        
        # Return session ID for progress tracking
        return jsonify({
            'success': True,
            'session_id': session_id,
            'message': 'Assessment started. Connect to /progress/{session_id} for updates.'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Assessment failed: {str(e)}'
        }), 500

@app.route('/api/progress/<session_id>')
def progress(session_id):
    """Server-Sent Events endpoint for progress updates"""
    
    def generate():
        # Get the progress queue for this session
        progress_queue = progress_queues.get(session_id)
        
        if not progress_queue:
            yield f"data: {json.dumps({'error': 'Session not found'})}\n\n"
            return
        
        try:
            while True:
                # Wait for progress update (timeout after 30 seconds)
                try:
                    progress_data = progress_queue.get(timeout=30)
                    
                    # Send progress update
                    yield f"data: {json.dumps(progress_data)}\n\n"
                    
                    # If complete or error, stop streaming
                    if progress_data.get('stage') in ['complete', 'error']:
                        break
                        
                except queue.Empty:
                    # Send keepalive
                    yield f": keepalive\n\n"
                    
        except GeneratorExit:
            pass
        finally:
            # Cleanup
            if session_id in progress_queues:
                del progress_queues[session_id]
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/stream/<session_id>')
def stream(session_id):
    """Server-Sent Events endpoint for progress updates (alternative endpoint)"""
    return progress(session_id)

@app.route('/api/result/<session_id>')
def get_result(session_id):
    """Get the final assessment result"""
    
    if session_id in completed_results:
        result = completed_results[session_id]
        
        # Clean up after retrieval
        del completed_results[session_id]
        
        return jsonify({
            'success': True,
            'assessment': result
        })
    else:
        return jsonify({
            'error': 'Result not found or not yet available'
        }), 404

@app.route('/api/history')
def history():
    """Get assessment history as JSON"""
    
    if not assessor:
        return jsonify({
            'error': 'Assessment service is not available.'
        }), 503
    
    try:
        assessments = assessor.get_assessment_history(limit=100)
        return jsonify({
            'success': True,
            'assessments': assessments
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to retrieve history: {str(e)}'
        }), 500

@app.route('/api/assessment/<int:assessment_id>')
def get_assessment_api(assessment_id):
    """Get a specific cached assessment by ID as JSON"""
    
    if not assessor:
        return jsonify({
            'error': 'Assessment service is not available.'
        }), 503
    
    try:
        # Get the specific assessment from cache
        assessment = assessor.get_assessment_by_id(assessment_id)
        
        if not assessment:
            return jsonify({
                'error': f'Assessment #{assessment_id} not found.'
            }), 404
        
        return jsonify({
            'success': True,
            'assessment': assessment
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to retrieve assessment: {str(e)}'
        }), 500

@app.route('/assessment/<int:assessment_id>')
def view_assessment(assessment_id):
    """View a specific cached assessment by ID"""
    
    if not assessor:
        return render_template('error.html', 
                             error='Assessment service is not available.')
    
    try:
        # Get the specific assessment from cache
        assessment = assessor.get_assessment_by_id(assessment_id)
        
        if not assessment:
            return render_template('error.html', 
                                 error=f'Assessment #{assessment_id} not found.'), 404
        
        # Render the assessment on the main page
        return render_template('index.html', 
                             cached_assessment=assessment,
                             show_cached=True)
        
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/compare')
def compare():
    """Compare multiple products"""
    return render_template('compare.html')

@app.route('/api/compare', methods=['POST'])
def api_compare():
    """Compare two products and return comparison data"""
    try:
        data = request.get_json()
        product1 = data.get('product1', '').strip()
        product2 = data.get('product2', '').strip()
        
        if not product1 or not product2:
            return jsonify({'error': 'Both product1 and product2 are required'}), 400
        
        if product1.lower() == product2.lower():
            return jsonify({'error': 'Please provide two different products to compare'}), 400
        
        print(f"[COMPARE] Comparing: '{product1}' vs '{product2}'")
        
        # Assess both products
        assessment1 = assessor.assess_product(product1)
        assessment2 = assessor.assess_product(product2)
        
        # Add input metadata
        assessment1['_input_metadata'] = {
            'raw_input': product1,
            'parsed_type': 'product_name',
            'detected_product': product1
        }
        assessment2['_input_metadata'] = {
            'raw_input': product2,
            'parsed_type': 'product_name',
            'detected_product': product2
        }
        
        # Extract trust scores (use 'score' key, not 'overall_score')
        trust_score_1 = assessment1.get('trust_score', {}).get('score') or 0
        trust_score_2 = assessment2.get('trust_score', {}).get('score') or 0
        
        # Extract CVE counts (use total_cves from security_posture)
        cve_count_1 = assessment1.get('security_posture', {}).get('total_cves', 0)
        cve_count_2 = assessment2.get('security_posture', {}).get('total_cves', 0)
        
        # Extract KEV counts (use total_kevs from security_posture)
        kev_count_1 = assessment1.get('security_posture', {}).get('total_kevs', 0)
        kev_count_2 = assessment2.get('security_posture', {}).get('total_kevs', 0)
        
        # Calculate comparison metrics
        comparison_metrics = {
            'trust_score': {
                'product1': trust_score_1,
                'product2': trust_score_2,
                'difference': round(trust_score_1 - trust_score_2, 2)
            },
            'cve_count': {
                'product1': cve_count_1,
                'product2': cve_count_2,
                'difference': cve_count_1 - cve_count_2
            },
            'kev_count': {
                'product1': kev_count_1,
                'product2': kev_count_2,
                'difference': kev_count_1 - kev_count_2
            }
        }
        
        # Generate recommendation
        recommendation = None
        if trust_score_1 != trust_score_2:
            winner = product1 if trust_score_1 > trust_score_2 else product2
            winner_score = max(trust_score_1, trust_score_2)
            loser_score = min(trust_score_1, trust_score_2)
            score_diff = abs(trust_score_1 - trust_score_2)
            
            reasons = []
            reasons.append(f"Higher trust score ({winner_score:.1f} vs {loser_score:.1f})")
            
            if trust_score_1 > trust_score_2:
                if cve_count_1 < cve_count_2:
                    reasons.append(f"Fewer CVEs ({cve_count_1} vs {cve_count_2})")
                if kev_count_1 < kev_count_2:
                    reasons.append(f"Fewer KEV exploits ({kev_count_1} vs {kev_count_2})")
            else:
                if cve_count_2 < cve_count_1:
                    reasons.append(f"Fewer CVEs ({cve_count_2} vs {cve_count_1})")
                if kev_count_2 < kev_count_1:
                    reasons.append(f"Fewer KEV exploits ({kev_count_2} vs {kev_count_1})")
            
            recommendation = {
                'product': winner,
                'reason': ' • '.join(reasons) if reasons else f"Better overall security assessment"
            }
        
        print(f"[COMPARE] Winner: {recommendation['product'] if recommendation else 'Tie'}")
        
        return jsonify({
            'product1': assessment1,
            'product2': assessment2,
            'recommendation': recommendation,
            'comparison_metrics': comparison_metrics
        })
        
    except Exception as e:
        print(f"[COMPARE ERROR] {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health():
    """Health check endpoint"""
    
    health_status = {
        'status': 'healthy' if assessor else 'unhealthy',
        'timestamp': datetime.now().isoformat(),
        'components': {
            'assessor': assessor is not None,
            'gemini_api': bool(Config.GEMINI_API_KEY),
            'producthunt_api': bool(Config.PRODUCTHUNT_API_KEY)
        }
    }
    
    status_code = 200 if assessor else 503
    return jsonify(health_status), status_code

@app.errorhandler(404)
def not_found(e):
    """404 error handler - serve React app for client-side routing"""
    if use_react_frontend and not request.path.startswith('/api'):
        return send_from_directory(app.static_folder, 'index.html')
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def server_error(e):
    """500 error handler"""
    if use_react_frontend:
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('error.html', error='Internal server error'), 500

if __name__ == '__main__':
    if not Config.GEMINI_API_KEY:
        logger.warning("GEMINI_API_KEY not set! Please configure in .env file")
    
    # Get port from environment variable or default to 5000
    port = int(os.environ.get('PORT', 5000))
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=Config.DEBUG
    )
