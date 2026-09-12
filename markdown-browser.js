import { marked } from 'marked';
import DOMPurify from 'dompurify';

window.renderNoteMarkdown = (source, container) => {
  const html = marked.parse(source, { gfm: true, breaks: true, async: false });
  container.innerHTML = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['p','br','hr','h1','h2','h3','h4','h5','h6','strong','em','del','blockquote','ul','ol','li','pre','code','a','table','thead','tbody','tr','th','td','input'],
    ALLOWED_ATTR: ['href','title','align','type','checked','disabled','start'],
    ALLOW_DATA_ATTR: false, ALLOW_ARIA_ATTR: false
  });
  container.querySelectorAll('a').forEach(link => {
    const href = link.getAttribute('href') || '';
    if (!/^(https?:\/\/|mailto:|#)/i.test(href)) link.removeAttribute('href');
    else { link.target = '_blank'; link.rel = 'noopener noreferrer'; }
  });
  container.querySelectorAll('input').forEach(input => {
    input.type = 'checkbox'; input.disabled = true;
  });
  container.querySelectorAll('table').forEach(table => {
    const wrapper = document.createElement('div');
    wrapper.className = 'markdown-table-scroll'; wrapper.tabIndex = 0;
    wrapper.setAttribute('role', 'region'); wrapper.setAttribute('aria-label', '表格，可横向滚动');
    table.replaceWith(wrapper); wrapper.appendChild(table);
  });
};
