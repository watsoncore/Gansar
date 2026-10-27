/* Local, editable source-to-slot mapping. No directory access or network API.
 * Paths are relative to htmlG/assets and validated as a single local filename.
 * `animated` is an audited hint for reduced-motion loading, never a UI label.
 * Keep a slot's own candidates together; no fallback to another slot's photo.
 * Current .webp and motion2 extensions do not match their actual JPEG bytes;
 * files are deliberately retained untouched. See MEDIA_GUIDE.md.
 */
window.GANSAR_ABOUT_MEDIA = Object.freeze({
  version: 1,
  slots: {
    background: {type: 'image', files: ['emma-background.webp', 'emma-background.jpg', 'emma-background.jpeg', 'emma-background.png'], animated: false},
    portrait: {type: 'image', files: ['emma-portrait.webp', 'emma-portrait.jpg', 'emma-portrait.jpeg', 'emma-portrait.png'], animated: false},
    gallery1: {type: 'image', files: ['emma-gallery-01.webp', 'emma-gallery-01.jpg', 'emma-gallery-01.jpeg', 'emma-gallery-01.png'], animated: false},
    gallery2: {type: 'image', files: ['emma-gallery-02.webp', 'emma-gallery-02.jpg', 'emma-gallery-02.jpeg', 'emma-gallery-02.png'], animated: false},
    motion1: {type: 'auto', files: ['emma-motion-01.gif', 'emma-motion-01.webp', 'emma-motion-01.mp4', 'emma-motion-01.webm'], animated: true},
    // This specific existing file is a single-frame JPEG, not an animation.
    motion2: {type: 'auto', files: ['emma-motion-02.gif', 'emma-motion-02.webp', 'emma-motion-02.mp4', 'emma-motion-02.webm'], animated: false},
    // A distinct genuine user-supplied GIF, never used as another slot's fallback.
    kiss: {type: 'image', files: ['Emma Watson Kiss GIF.gif'], animated: true}
  }
});
