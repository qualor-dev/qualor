import { closePopover } from './popover';

describe('closePopover', () => {
  function popover(matches: (selector: string) => boolean, hide?: () => void): HTMLElement {
    const element = document.createElement('div');
    (element as unknown as { matches: typeof matches }).matches = matches;
    if (hide) (element as unknown as { hidePopover: () => void }).hidePopover = hide;
    return element;
  }

  it('does nothing without the Popover API', () => {
    expect(() => closePopover(document.createElement('div'))).not.toThrow();
  });

  it('counts an element whose :popover-open check throws as closed', () => {
    const hide = vi.fn();
    closePopover(
      popover(() => {
        throw new SyntaxError('not a selector');
      }, hide),
    );
    expect(hide).not.toHaveBeenCalled();
  });

  it('hides an open popover once', () => {
    const hide = vi.fn();
    closePopover(popover((s) => s === ':popover-open', hide));
    expect(hide).toHaveBeenCalledTimes(1);
  });

  it('leaves a closed popover alone', () => {
    const hide = vi.fn();
    closePopover(popover(() => false, hide));
    expect(hide).not.toHaveBeenCalled();
  });
});
