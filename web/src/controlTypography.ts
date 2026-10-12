// Scope value typography to the real input, leaving labels and normal forms alone.
export const monospaceFontFamily = 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace';
export const monospaceInputSx = {
  '& .MuiInputBase-input': {
    fontFamily: monospaceFontFamily,
    '&::placeholder': {fontFamily: monospaceFontFamily, fontSize: 'inherit'},
  },
};
export const compactControlFontSx = {fontSize: '12px', lineHeight: '18px'};
export const compactControlSx = {
  '& .MuiInputBase-root': {...compactControlFontSx, height: '32px', boxSizing: 'border-box'},
  '& .MuiInputBase-root .MuiInputBase-input': {
    ...compactControlFontSx, boxSizing: 'border-box', height: '32px', minHeight: 0, padding: '7px 10px',
  },
  '& .MuiInputBase-root .MuiInputBase-input.MuiSelect-select': {paddingRight: '28px'},
  '& .MuiInputBase-adornedStart': {paddingLeft: '10px'},
  '& .MuiInputBase-adornedStart .MuiInputBase-input': {paddingLeft: 0},
  '& .MuiInputLabel-root': {
    ...compactControlFontSx, transform: 'translate(10px, 7px) scale(1)',
    '&.MuiInputLabel-shrink': {transform: 'translate(10px, -6px) scale(0.75)'},
  },
  '& .MuiOutlinedInput-notchedOutline': {padding: '0 5px'},
  '& .MuiOutlinedInput-notchedOutline legend': {fontSize: '0.75em'},
};
