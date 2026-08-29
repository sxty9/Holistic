// Copying text, on a page that is not a secure context.
//
// http://holistic.local is plain HTTP on a LAN name, and only HTTPS and
// loopback count as secure. So `navigator.clipboard` is not merely blocked, it
// is UNDEFINED — a copy button written the modern way throws on click and the
// page looks broken rather than unsupported.
//
// document.execCommand('copy') is deprecated and still works everywhere here.
// It needs a real selection, so it needs a real element.
//
// When even that fails the answer is not a message saying copying failed. It is
// to leave the text selected, so the reader can copy it the way they would copy
// anything else.
export function copyText(text: string): boolean {
  const ta = document.createElement('textarea');
  ta.value = text;
  // Off-screen rather than hidden: a display:none element cannot be selected,
  // and a visible one scrolls the page out from under whoever clicked.
  ta.style.position = 'fixed';
  ta.style.top = '-1000px';
  ta.setAttribute('readonly', '');
  document.body.appendChild(ta);
  try {
    ta.select();
    ta.setSelectionRange(0, text.length);
    return document.execCommand('copy');
  } catch {
    return false;
  } finally {
    document.body.removeChild(ta);
  }
}
