-- WRK Lua script for mixed HTTP requests (normal + attacks)

request_counter = 0

-- List of test URLs (70% normal, 30% attacks)
paths = {
    -- Normal requests (70%)
    "/", "/index.html", "/api/users", "/static/style.css", 
    "/images/logo.png", "/api/products", "/about",
    
    -- XSS attacks (10%)
    "/?q=<script>alert('xss')</script>",
    "/?name=<img src=x onerror=alert(1)>",
    
    -- SQL Injection (10%)
    "/?id=1' OR 1=1--",
    "/?id=1 UNION SELECT * FROM users",
    
    -- Path Traversal (5%)
    "/../../etc/passwd",
    "/../../../windows/system32",
    
    -- Scanner patterns (5%)
    "/admin/login", "/.git/config"
}

-- User agents (90% normal, 10% scanners)
user_agents = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "curl/7.68.0",
    "sqlmap/1.0",  -- Scanner
    "nikto/2.1.5"  -- Scanner
}

request = function()
    request_counter = request_counter + 1
    
    -- Select path (weighted random)
    local path_index = (request_counter % #paths) + 1
    local path = paths[path_index]
    
    -- Select user agent (weighted random)
    local ua_index = (request_counter % #user_agents) + 1
    local user_agent = user_agents[ua_index]
    
    return wrk.format("GET", path, {["User-Agent"] = user_agent})
end

done = function(summary, latency, requests)
    io.write("\n")
    io.write("========================================\n")
    io.write("  Test Results Summary\n")
    io.write("========================================\n")
    io.write(string.format("  Total Requests: %d\n", summary.requests))
    io.write(string.format("  Duration: %.2fs\n", summary.duration / 1000000))
    io.write(string.format("  Requests/sec: %.2f\n", summary.requests / (summary.duration / 1000000)))
    io.write(string.format("  Avg Latency: %.2fms\n", latency.mean / 1000))
    io.write(string.format("  Max Latency: %.2fms\n", latency.max / 1000))
    io.write(string.format("  Errors: %d\n", summary.errors.connect + summary.errors.read + summary.errors.write + summary.errors.status + summary.errors.timeout))
    io.write("========================================\n")
end
