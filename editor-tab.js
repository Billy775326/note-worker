// Tab edits indentation only inside content editors; other controls retain native navigation.
(() => {
  const isEditor = element => element instanceof HTMLTextAreaElement &&
    ['note-content', 'main-content', 'crawler-source'].includes(element.id);
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !event.isComposing && isEditor(document.activeElement)) {
      event.preventDefault();
      event.stopImmediatePropagation();
      document.activeElement.blur();
    }
  }, true);
  document.addEventListener('pointerdown', event => {
    const editor = document.activeElement;
    if (isEditor(editor) && event.target !== editor) editor.blur();
  }, true);
  document.addEventListener('keydown', event => {
    const editor = event.target;
    if (event.key !== 'Tab' || event.isComposing || event.ctrlKey || event.metaKey || event.altKey ||
        !(editor instanceof HTMLTextAreaElement) || editor.disabled || editor.readOnly ||
        !['note-content', 'main-content', 'crawler-source'].includes(editor.id)) return;
    event.preventDefault();
    const value = editor.value;
    const start = editor.selectionStart;
    const end = editor.selectionEnd;
    const direction = editor.selectionDirection;
    const scrollTop = editor.scrollTop;
    const scrollLeft = editor.scrollLeft;
    let replaceStart = start, replaceEnd = end, replacement = '\t';
    let nextStart = start + 1, nextEnd = start + 1;
    if (event.shiftKey || value.slice(start, end).includes('\n')) {
      replaceStart = value.lastIndexOf('\n', start - 1) + 1;
      if (start === 0) replaceStart = 0;
      const lastSelected = end > start && value[end - 1] === '\n' ? end - 1 : end;
      const nextBreak = value.indexOf('\n', lastSelected);
      replaceEnd = nextBreak === -1 ? value.length : nextBreak;
      const lines = value.slice(replaceStart, replaceEnd).split('\n');
      const changes = lines.map(line => event.shiftKey ? -(line.match(/^(?:\t| {1,4})/)?.[0].length || 0) : 1);
      replacement = lines.map((line, i) => event.shiftKey ? line.slice(-changes[i]) : '\t' + line).join('\n');
      if (event.shiftKey && changes.every(change => change === 0)) return;
      nextStart = event.shiftKey ? Math.max(replaceStart, start + changes[0]) : start + 1;
      nextEnd = Math.max(nextStart, end + changes.reduce((sum, change) => sum + change, 0));
    }
    editor.setSelectionRange(replaceStart, replaceEnd);
    // Native editing keeps browser undo history. Fallback still emits input for autosave.
    let edited = false;
    try { edited = document.execCommand('insertText', false, replacement); } catch {}
    if (!edited) {
      editor.setRangeText(replacement, replaceStart, replaceEnd, 'end');
      editor.dispatchEvent(new Event('input', { bubbles: true }));
    }
    editor.setSelectionRange(nextStart, nextEnd, direction);
    editor.scrollTop = scrollTop;
    editor.scrollLeft = scrollLeft;
  });
})();
