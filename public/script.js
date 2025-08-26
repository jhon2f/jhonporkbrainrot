// State
let state = {
  token: null,
  searchResults: [],
  idleakResults: null,
  combos: [],
  filtered: []
};

// Elements
const elements = {};
['searchType', 'osintType', 'searchInput', 'searchBtn', 'searchTime', 'results', 'searchActions',
 'firstName', 'lastName', 'address', 'city', 'state', 'zip', 'ssn', 'dob', 'phone1', 
 'idleakTime', 'idleakResults', 'idleakActions',
 'comboKeyword', 'comboLimit', 'comboLimitValue', 'filters', 'comboCount', 'comboResults', 'comboActions',
 'editor', 'editorText', 'editorCount', 'validCount', 'emailCount', 'userCount', 'recordCount', 'status']
.forEach(id => elements[id] = document.getElementById(id));

// Init
async function init() {
  await getToken();
  await fetchRecordCount();
  setupEvents();
  updateStatus();
}

async function getToken() {
  try {
    const res = await fetch('/api/auth', { method: 'POST' });
    const data = await res.json();
    state.token = data.token;
  } catch (err) {
    console.error('Auth failed:', err);
  }
}

async function fetchRecordCount() {
  try {
    const result = await query('SELECT count() as total FROM osint.raw_lines');
    elements.recordCount.textContent = result?.data?.[0]?.total?.toLocaleString() || 'Error';
  } catch (err) {
    elements.recordCount.textContent = 'Error';
  }
}

function updateStatus() {
  const isOnline = elements.recordCount.textContent !== 'Error';
  elements.status.textContent = isOnline ? '●ONLINE' : '●OFFLINE';
  elements.status.style.color = isOnline ? '#059669' : '#dc2626';
}

function setupEvents() {
  // Tabs
  document.querySelectorAll('.tab').forEach(btn => {
    btn.onclick = () => switchTab(btn.dataset.tab);
  });
  
  // Search
  elements.searchType.onchange = () => {
    elements.osintType.classList.toggle('hidden', !['osint', 'both'].includes(elements.searchType.value));
  };
  elements.searchBtn.onclick = performSearch;
  elements.searchInput.onkeypress = e => e.key === 'Enter' && performSearch();
  
  // Combo
  elements.comboLimit.oninput = () => {
    elements.comboLimitValue.textContent = (elements.comboLimit.value / 1000) + 'K';
  };
}

function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tab);
  });
  document.querySelectorAll('.tab-content').forEach(content => {
    content.classList.toggle('active', content.id === tab);
  });
}

async function performSearch() {
  const term = elements.searchInput.value.trim();
  const type = elements.searchType.value;
  
  if (!term) return alert('Enter search term');
  
  setLoading(true);
  elements.searchTime.textContent = 'Searching...';
  elements.results.innerHTML = '';
  
  const start = Date.now();
  
  try {
    let results = [];
    
    if (['database', 'both'].includes(type)) {
      const dbResults = await searchDatabase(term);
      if (dbResults.length) results.push({ type: 'database', data: dbResults });
    }
    
    if (['osint', 'both'].includes(type)) {
      const osintResults = await searchOSINT(term);
      if (osintResults) results.push({ type: 'osint', data: osintResults });
    }
    
    const duration = ((Date.now() - start) / 1000).toFixed(2);
    
    if (results.length) {
      displayResults(results);
      elements.searchActions.classList.remove('hidden');
      elements.searchTime.textContent = `Found results in ${duration}s`;
    } else {
      elements.results.innerHTML = '<div style="padding: 20px; text-align: center; color: #666;">No results found</div>';
      elements.searchTime.textContent = `No results in ${duration}s`;
    }
  } catch (err) {
    elements.results.innerHTML = '<div style="padding: 20px; color: #dc2626;">Search failed</div>';
    elements.searchTime.textContent = 'Search failed';
  } finally {
    setLoading(false);
  }
}

async function searchDatabase(term) {
  const result = await query(`SELECT line FROM osint.raw_lines WHERE position(line, '${term.replace(/'/g, "''")}') > 0 LIMIT 20`);
  return result?.data || [];
}

async function searchOSINT(term) {
  try {
    const osintType = elements.osintType.value;
    const res = await fetch('/api/lookup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Session-Token': state.token
      },
      body: JSON.stringify({ query: term, type: osintType })
    });
    const data = await res.json();
    return data.investigation_results;
  } catch (err) {
    return null;
  }
}

function displayResults(results) {
  elements.results.innerHTML = '';
  
  results.forEach(result => {
    if (result.type === 'database') {
      displayDBResults(result.data);
    } else {
      displayOSINTResults(result.data);
    }
  });
  
  state.searchResults = results;
}

function displayDBResults(data) {
  elements.results.innerHTML = '';

  const section = document.createElement('div');
  section.innerHTML = '<h3 style="color: #2563eb; margin: 20px 0;">Database Results</h3>';

  const seen = new Set();
  let count = 0;

  data.forEach(item => {
    const line = item.line || '';
    if (seen.has(line)) return;
    seen.add(line);
    count++;

    const block = document.createElement('div');
    block.className = 'result-block';
    block.innerHTML = `
      <div class="block-header">Entry ${count}</div>
      <pre class="raw-block">${sanitize(line)}</pre>
    `;
    section.appendChild(block);
  });

  const countDiv = document.createElement('div');
  countDiv.style = "margin: 10px 0; font-weight: bold; color: #059669;";
  countDiv.textContent = `Found ${count.toLocaleString()} unique entries`;
  section.insertBefore(countDiv, section.firstChild);

  elements.results.appendChild(section);
}


function displayOSINTResults(data) {
  elements.results.innerHTML = '';

  const section = document.createElement('div');
  section.innerHTML = '<h3 style="color: #2563eb; margin: 20px 0;">OSINT Results</h3>';

  // Check for investigation_results first, then fallback to results
  const results = data?.investigation_results?.results || data?.results;
  
  if (!data || !results) {
    section.innerHTML += '<div style="padding: 20px; text-align: center; color: #666;">No OSINT results found</div>';
    elements.results.appendChild(section);
    return;
  }

  // Loop over each provider (leakcheck, snusbase, intelvault, etc.)
  Object.entries(results).forEach(([provider, result]) => {
    const providerSection = document.createElement('div');
    providerSection.innerHTML = `<h4 style="color:#059669; margin: 16px 0;">${provider.toUpperCase()}</h4>`;

    // Handle different error formats
    if (result.error || result.status === "timeout" || result.status === "http_error" || (result.success === false && result.error)) {
      let errorMessage = '';
      
      if (typeof result.error === 'object' && result.error !== null) {
        // Handle nested error objects like intelvault
        errorMessage = result.error.error || result.error.message || JSON.stringify(result.error);
      } else {
        errorMessage = result.error || result.status || 'Unknown error';
      }
      
      providerSection.innerHTML += `<div style="padding: 10px; color: #dc2626;">Error: ${sanitize(errorMessage)}</div>`;
    } 
    // Handle LeakCheck format
    else if (result.found && Array.isArray(result.result) && result.result.length > 0) {
      result.result.forEach(entry => {
        const block = document.createElement('div');
        block.className = 'result-block';
        
        let blockContent = `<div class="block-header">${sanitize(entry.username || entry.email || entry.full_name || 'Unknown')}</div><div class="block-body">`;
        
        // Display all available fields dynamically
        Object.entries(entry).forEach(([key, value]) => {
          if (key === 'source' && typeof value === 'object') {
            blockContent += `<div><strong>Source:</strong> ${sanitize(value.name || 'Unknown')}</div>`;
            if (value.breach_date) {
              blockContent += `<div><strong>Breach Date:</strong> ${sanitize(value.breach_date)}</div>`;
            }
          } else if (key === 'origin' && Array.isArray(value)) {
            blockContent += `<div><strong>Origins:</strong> ${value.map(o => sanitize(o)).join(', ')}</div>`;
          } else if (key === 'fields') {
            // Skip fields array as it's metadata
          } else if (typeof value === 'string' || typeof value === 'number') {
            const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            blockContent += `<div><strong>${displayKey}:</strong> ${sanitize(value.toString())}</div>`;
          }
        });
        
        blockContent += '</div>';
        block.innerHTML = blockContent;
        providerSection.appendChild(block);
      });
    }
    // Handle Snusbase format
    else if (result.results && typeof result.results === 'object') {
      const snusResults = result.results;
      if (Object.keys(snusResults).length === 0) {
        providerSection.innerHTML += '<div style="padding: 10px; color: #666;">No results found</div>';
      } else {
        Object.entries(snusResults).forEach(([database, entries]) => {
          if (Array.isArray(entries) && entries.length > 0) {
            entries.forEach(entry => {
              const block = document.createElement('div');
              block.className = 'result-block';
              
              let blockContent = `<div class="block-header">${sanitize(database)}</div><div class="block-body">`;
              
              Object.entries(entry).forEach(([key, value]) => {
                if (key.startsWith('_')) return; // Skip internal fields
                const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                blockContent += `<div><strong>${displayKey}:</strong> ${sanitize(value.toString())}</div>`;
              });
              
              blockContent += '</div>';
              block.innerHTML = blockContent;
              providerSection.appendChild(block);
            });
          }
        });
      }
    }
    // Handle Intelvault format
    else if (result.results && Array.isArray(result.results)) {
      result.results.forEach(resultGroup => {
        if (resultGroup.data && Array.isArray(resultGroup.data)) {
          resultGroup.data.forEach(entry => {
            const block = document.createElement('div');
            block.className = 'result-block';
            
            let blockContent = `<div class="block-header">${sanitize(resultGroup.index || 'Unknown Database')}</div><div class="block-body">`;
            
            Object.entries(entry).forEach(([key, value]) => {
              if (typeof value === 'string' || typeof value === 'number') {
                const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                blockContent += `<div><strong>${displayKey}:</strong> ${sanitize(value.toString())}</div>`;
              }
            });
            
            blockContent += '</div>';
            block.innerHTML = blockContent;
            providerSection.appendChild(block);
          });
        } else {
          // Handle single entry format
          const block = document.createElement('div');
          block.className = 'result-block';
          
          let blockContent = `<div class="block-header">${sanitize(resultGroup.index || 'Unknown Database')}</div><div class="block-body">`;
          
          Object.entries(resultGroup).forEach(([key, value]) => {
            if (key === 'index') return; // Skip index as it's used in header
            if (typeof value === 'string' || typeof value === 'number') {
              const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
              blockContent += `<div><strong>${displayKey}:</strong> ${sanitize(value.toString())}</div>`;
            }
          });
          
          blockContent += '</div>';
          block.innerHTML = blockContent;
          providerSection.appendChild(block);
        }
      });
    }
    // Handle empty or no results
    else if (result.size === 0 || result.took !== undefined) {
      providerSection.innerHTML += '<div style="padding: 10px; color: #666;">No results found</div>';
    }
    else {
      providerSection.innerHTML += '<div style="padding: 10px; color: #666;">No results found</div>';
    }

    section.appendChild(providerSection);
  });

  elements.results.appendChild(section);
}

function parseLine(line) {
  const parts = line.split(':');
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  
  let email = '', username = '', password = '';
  
  if (parts.length >= 2) {
    const first = parts[0];
    if (emailRegex.test(first)) {
      email = first;
      username = first.split('@')[0];
    } else {
      username = first;
    }
    password = parts[parts.length - 1];
  }
  
  return { email, username, password, raw: line };
}

async function extractCombos() {
  const keyword = elements.comboKeyword.value.trim();
  const limit = parseInt(elements.comboLimit.value, 10) || 100; // default to 100 if invalid
  if (!keyword) return alert('Enter keyword');

  setLoading(true);
  elements.comboResults.innerHTML = '';
  elements.filters.classList.add('hidden');
  elements.comboActions.classList.add('hidden');

  try {
    let offset = 0;
    let allRows = [];
    let batchSize = 1000; // fetch 1000 rows per batch
    let keepFetching = true;

    while (keepFetching) {
      const result = await query(`
        SELECT line
        FROM osint.raw_lines
        WHERE position(line, '${keyword.replace(/'/g, "''")}') > 0
        LIMIT ${batchSize} OFFSET ${offset}
      `);

      if (!result?.data?.length) break;

      allRows.push(...result.data.map(r => r.line));
      offset += batchSize;

      // Stop if we reached the user-requested limit
      if (allRows.length >= limit) {
        allRows = allRows.slice(0, limit);
        keepFetching = false;
      }
    }

    if (allRows.length) {
      state.combos = allRows;
      state.filtered = [...state.combos];

      displayComboCount();
      displayComboPreview();
      elements.filters.classList.remove('hidden');
      elements.comboActions.classList.remove('hidden');
    } else {
      alert('No combos found');
    }

  } catch (err) {
    console.error('Query error:', err);
    alert('Extraction failed: ' + (err.message || err));
  } finally {
    setLoading(false);
  }
}


function applyFilters() {
  let filtered = [...state.combos];
  
  const emailFilter = document.getElementById('emailFilter').checked;
  const userFilter = document.getElementById('userFilter').checked;
  const removeUrl = document.getElementById('removeUrl').checked;
  const removeDupe = document.getElementById('removeDupe').checked;
  
  // Only apply URL removal if the checkbox is checked
  if (removeUrl) {
    filtered = filtered.map(line => {
      let cleanedLine = line.trim();
      
      // Remove URLs with various protocols and formats
      cleanedLine = cleanedLine
        // Remove URLs at the start with : separator
        .replace(/^https?:\/\/[^:|]+[:|]/g, '')
        // Remove URLs at the start with | separator  
        .replace(/^https?:\/\/[^|]+\|/g, '')
        // Remove URLs at the end with various separators
        .replace(/[:|]https?:\/\/[^\s|:]*$/g, '')
        // Remove URLs in the middle
        .replace(/https?:\/\/[^\s|:]*[:|]/g, '')
        // Remove domain-only URLs (like help.steampowered.com, store.steampowered.com)
        .replace(/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[\/\w-]*[:|]/g, '')
        // Remove trailing URLs after separators
        .replace(/[:|][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[\/\w-]*$/g, '')
        // Clean up steamcommunity format (https://steamcommunity.com|user|pass#)
        .replace(/^https?:\/\/[^|]+\|([^|]+)\|([^#]+)#?.*$/, '$1:$2')
        // Remove any remaining URL fragments
        .replace(/https?:\/\/[^\s|:]*/, '');
      
      return cleanedLine;
    });
    
    // Parse and standardize the format to username:password only if URL removal is enabled
    filtered = filtered.map(line => {
      let cleanedLine = line.trim();
      
      // Skip empty lines
      if (!cleanedLine) return '';
      
      // Handle different separators and formats
      let parts = [];
      
      // Try different separators in order of preference
      if (cleanedLine.includes('|')) {
        parts = cleanedLine.split('|').map(p => p.trim()).filter(p => p);
      } else if (cleanedLine.includes(':')) {
        parts = cleanedLine.split(':').map(p => p.trim()).filter(p => p);
      } else if (cleanedLine.includes(' ')) {
        // Handle space-separated, but be careful with emails
        if (cleanedLine.includes('@')) {
          // If it contains @, try to preserve email format
          const spaceIndex = cleanedLine.indexOf(' ');
          if (spaceIndex > 0) {
            parts = [cleanedLine.substring(0, spaceIndex), cleanedLine.substring(spaceIndex + 1)].filter(p => p.trim());
          } else {
            parts = [cleanedLine];
          }
        } else {
          parts = cleanedLine.split(/\s+/).filter(p => p);
        }
      } else {
        // Single item, no separator found
        parts = [cleanedLine];
      }
      
      // Filter out obvious non-credential parts
      parts = parts.filter(part => {
        // Remove empty parts
        if (!part || part.trim() === '') return false;
        // Remove obvious URLs that might have slipped through
        if (part.match(/^https?:\/\//)) return false;
        // Remove domain-only parts that look like URLs
        if (part.match(/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[\/\w-]*$/) && !part.includes('@')) return false;
        // Remove parts that are just special characters or numbers
        if (part.match(/^[#\-_=+]*$/)) return false;
        return true;
      });
      
      // Handle different cases based on number of parts
      if (parts.length >= 2) {
        // Take first two parts as username:password
        return `${parts[0]}:${parts[1]}`;
      } else if (parts.length === 1) {
        // Single part - could be username only or malformed
        return parts[0];
      }
      
      return '';
    }).filter(line => line.trim() !== ''); // Remove empty lines
    
    // Final cleanup - remove any lines that are just separators or invalid
    filtered = filtered.filter(line => {
      const trimmed = line.trim();
      // Remove lines that are just separators
      if (trimmed.match(/^[:|]+$/)) return false;
      // Remove lines that are too short to be valid credentials
      if (trimmed.length < 2) return false;
      // Remove lines that are just URLs
      if (trimmed.match(/^https?:\/\//)) return false;
      return true;
    });
  }
  
  // Apply email/username filters only if one of them is checked
  if (emailFilter && !userFilter) {
    filtered = filtered.filter(line => {
      // Extract username part (before first : or | or space)
      const username = line.split(/[:|]/)[0].trim();
      return username && username.includes('@');
    });
  } else if (userFilter && !emailFilter) {
    filtered = filtered.filter(line => {
      // Extract username part (before first : or | or space)
      const username = line.split(/[:|]/)[0].trim();
      return username && !username.includes('@');
    });
  }
  
  // Remove duplicates only if the checkbox is checked
  if (removeDupe) {
    filtered = [...new Set(filtered)];
  }
  
  state.filtered = filtered;
  displayComboCount();
  displayComboPreview();
}

async function searchIdLeak() {
  const params = {
    firstName: elements.firstName.value.trim(),
    lastName: elements.lastName.value.trim(),
    address: elements.address.value.trim(),
    city: elements.city.value.trim(),
    state: elements.state.value.trim(),
    zip: elements.zip.value.trim(),
    ssn: elements.ssn.value.trim(),
    dob: elements.dob.value.trim(),
    phone1: elements.phone1.value.trim()
  };
  
  // Remove empty fields
  Object.keys(params).forEach(key => {
    if (!params[key]) delete params[key];
  });
  
  if (Object.keys(params).length === 0) {
    return alert('Enter at least one search parameter');
  }
  
  setLoading(true);
  elements.idleakTime.textContent = 'Searching IdLeak...';
  elements.idleakResults.innerHTML = '';
  
  const start = Date.now();
  
  try {
    const res = await fetch('/api/lookup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Session-Token': state.token
      },
      body: JSON.stringify({ query: JSON.stringify(params), type: 'idleak' })
    });
    
    const data = await res.json();
    const duration = ((Date.now() - start) / 1000).toFixed(2);
    
    if (data.success && data.investigation_results) {
      state.idleakResults = data.investigation_results;
      displayIdLeakResults(data.investigation_results);
      elements.idleakActions.classList.remove('hidden');
      elements.idleakTime.textContent = `Found results in ${duration}s`;
    } else {
      elements.idleakResults.innerHTML = '<div style="padding: 20px; text-align: center; color: #666;">No results found</div>';
      elements.idleakTime.textContent = `No results in ${duration}s`;
    }
  } catch (err) {
    console.error('IdLeak search failed:', err);
    elements.idleakResults.innerHTML = '<div style="padding: 20px; color: #dc2626;">Search failed</div>';
    elements.idleakTime.textContent = 'Search failed';
  } finally {
    setLoading(false);
  }
}

function displayIdLeakResults(data) {
  elements.idleakResults.innerHTML = '';
  
  const section = document.createElement('div');
  section.innerHTML = '<h3 style="color: #2563eb; margin: 20px 0;">IdLeak Results</h3>';
  
  // Display NPD records
  if (data.npd && data.npd.length > 0) {
    const npdSection = document.createElement('div');
    npdSection.innerHTML = '<h4 style="color: #059669; margin: 16px 0;">NPD Records</h4>';
    
    data.npd.forEach(record => {
      const personDiv = document.createElement('div');
      personDiv.className = 'person-record';
      
      const name = [record.firstname, record.middlename, record.lastname].filter(Boolean).join(' ');
      
      personDiv.innerHTML = `
        <div class="record-header">${sanitize(name)}</div>
        ${record.dob ? `<div class="record-field"><strong>DOB:</strong> ${sanitize(record.dob)}</div>` : ''}
        ${record.address ? `<div class="record-field"><strong>Address:</strong> ${sanitize(record.address)}</div>` : ''}
        ${record.city ? `<div class="record-field"><strong>City:</strong> ${sanitize(record.city)} ${sanitize(record.st)} ${sanitize(record.zip)}</div>` : ''}
        ${record.phone1 ? `<div class="record-field"><strong>Phone:</strong> ${sanitize(record.phone1)}</div>` : ''}
        ${record.ssn ? `<div class="record-field"><strong>SSN:</strong> ${sanitize(record.ssn)}</div>` : ''}
        ${record.aka1fullname ? `<div class="record-field"><strong>AKA:</strong> ${sanitize(record.aka1fullname)}</div>` : ''}
        ${record.StartDat ? `<div class="record-field"><strong>Start Date:</strong> ${sanitize(record.StartDat)}</div>` : ''}
      `;
      
      npdSection.appendChild(personDiv);
    });
    
    section.appendChild(npdSection);
  }
  
  // Display M250 records
  if (data.m250 && data.m250.length > 0) {
    const m250Section = document.createElement('div');
    m250Section.innerHTML = '<h4 style="color: #d97706; margin: 16px 0;">M250 Records</h4>';
    
    data.m250.forEach(record => {
      const personDiv = document.createElement('div');
      personDiv.className = 'person-record';
      
      const name = [record.first_name, record.middle_name, record.last_name].filter(Boolean).join(' ');
      
      personDiv.innerHTML = `
        <div class="record-header">${sanitize(name)}</div>
        ${record.dob ? `<div class="record-field"><strong>DOB:</strong> ${sanitize(record.dob)}</div>` : ''}
        ${record.full_address ? `<div class="record-field"><strong>Address:</strong> ${sanitize(record.full_address)}</div>` : ''}
        ${record.city ? `<div class="record-field"><strong>City:</strong> ${sanitize(record.city)} ${sanitize(record.state)} ${sanitize(record.zip)}</div>` : ''}
        ${record.phone_1 ? `<div class="record-field"><strong>Phone 1:</strong> ${sanitize(record.phone_1)}</div>` : ''}
        ${record.phone_2 ? `<div class="record-field"><strong>Phone 2:</strong> ${sanitize(record.phone_2)}</div>` : ''}
        ${record.email ? `<div class="record-field"><strong>Email:</strong> ${sanitize(record.email)}</div>` : ''}
        ${record.gender ? `<div class="record-field"><strong>Gender:</strong> ${sanitize(record.gender)}</div>` : ''}
        ${record.county ? `<div class="record-field"><strong>County:</strong> ${sanitize(record.county)}</div>` : ''}
      `;
      
      m250Section.appendChild(personDiv);
    });
    
    section.appendChild(m250Section);
  }
  
  // Display ATT records if any
  if (data.att && data.att.length > 0) {
    const attSection = document.createElement('div');
    attSection.innerHTML = '<h4 style="color: #dc2626; margin: 16px 0;">ATT Records</h4>';
    
    data.att.forEach(record => {
      const div = document.createElement('div');
      div.className = 'person-record';
      div.innerHTML = `<pre style="white-space: pre-wrap; font-size: 12px;">${JSON.stringify(record, null, 2)}</pre>`;
      attSection.appendChild(div);
    });
    
    section.appendChild(attSection);
  }
  
  if (!data.npd?.length && !data.m250?.length && !data.att?.length) {
    section.innerHTML += '<div style="padding: 20px; text-align: center; color: #666;">No records found</div>';
  }
  
  elements.idleakResults.appendChild(section);

  elements.comboCount.textContent = `${state.filtered.length.toLocaleString()} combos extracted`;
  elements.comboCount.classList.remove('hidden');
}

function displayComboPreview() {
  elements.comboResults.innerHTML = '';
  
  if (!state.filtered.length) {
    elements.comboResults.innerHTML = '<div style="padding: 20px; text-align: center; color: #666;">No combos found</div>';
    return;
  }
  
  const preview = state.filtered.slice(0, 100);
  const header = document.createElement('div');
  header.innerHTML = `<h3 style="margin: 16px 0;">Preview (first 100 of ${state.filtered.length.toLocaleString()})</h3>`;
  elements.comboResults.appendChild(header);
  
  preview.forEach(combo => {
    const line = document.createElement('div');
    line.style.cssText = 'padding: 4px 8px; border-bottom: 1px solid #333; font-family: monospace; font-size: 12px;';
    line.textContent = combo;
    elements.comboResults.appendChild(line);
  });
}

function showEditor() {
  elements.editor.classList.remove('hidden');
  elements.editorText.value = state.filtered.join('\n');
  updateEditorStats();
  elements.editor.scrollIntoView({ behavior: 'smooth' });
}

function updateEditorStats() {
  const lines = elements.editorText.value.split('\n').filter(Boolean);
  const valid = lines.filter(l => l.includes(':'));
  const email = valid.filter(l => l.split(':')[0].includes('@'));
  const user = valid.filter(l => !l.split(':')[0].includes('@'));
  
  elements.editorCount.textContent = `(${lines.length.toLocaleString()})`;
  elements.validCount.textContent = valid.length.toLocaleString();
  elements.emailCount.textContent = email.length.toLocaleString();
  elements.userCount.textContent = user.length.toLocaleString();
}

function clearEditor() {
  if (confirm('Clear all data?')) {
    elements.editorText.value = '';
    updateEditorStats();
  }
}

function saveEditor() {
  state.filtered = elements.editorText.value.split('\n').filter(Boolean);
  displayComboCount();
  displayComboPreview();
  elements.editor.classList.add('hidden');
}

function exportData(type) {
  let data, filename;
  
  if (type === 'search') {
    if (!state.searchResults.length) return alert('No data to export');
    data = JSON.stringify({ results: state.searchResults, timestamp: new Date().toISOString() }, null, 2);
    filename = `search_results_${Date.now()}.json`;
  } else if (type === 'idleak') {
    if (!state.idleakResults) return alert('No IdLeak data to export');
    data = JSON.stringify({ results: state.idleakResults, timestamp: new Date().toISOString() }, null, 2);
    filename = `idleak_results_${Date.now()}.json`;
  } else {
    if (!state.filtered.length) return alert('No combos to export');
    data = state.filtered.join('\n');
    filename = `combos_${Date.now()}.txt`;
  }
  
  const blob = new Blob([data], { type: type === 'combo' ? 'text/plain' : 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function clearResults(type) {
  if (type === 'search') {
    state.searchResults = [];
    elements.results.innerHTML = '';
    elements.searchTime.textContent = '';
    elements.searchActions.classList.add('hidden');
  } else if (type === 'idleak') {
    state.idleakResults = null;
    elements.idleakResults.innerHTML = '';
    elements.idleakTime.textContent = '';
    elements.idleakActions.classList.add('hidden');
  } else {
    state.combos = [];
    state.filtered = [];
    elements.comboResults.innerHTML = '';
    elements.comboCount.textContent = '';
    elements.filters.classList.add('hidden');
    elements.comboActions.classList.add('hidden');
    elements.editor.classList.add('hidden');
  }
}

async function query(sql) {
  const res = await fetch('/api/clickhouse', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: sql })
  });
  return await res.json();
}

function displayComboCount() {
  if (!elements.comboCount) return;
  elements.comboCount.textContent = `${state.filtered.length.toLocaleString()} combos extracted`;
  elements.comboCount.classList.remove('hidden');
}


function sanitize(text) {
  return String(text || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function setLoading(loading) {
  document.body.style.cursor = loading ? 'wait' : '';
  elements.searchBtn.disabled = loading;
}

// Event listeners for editor
elements.editorText.oninput = updateEditorStats;

// Initialize on load
document.addEventListener('DOMContentLoaded', init);

// Update status every 30 seconds
setInterval(updateStatus, 30000);