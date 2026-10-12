//! One in-memory device choice, bound to backend session and exact Origin.
//! Reset revisions prevent a canceled task from restoring a cleared choice.
use super::{wire::Device, Binding};
use std::sync::{Arc, Mutex};
#[derive(Default)]
struct Memory {
    revision: u64,
    selected: Option<(String, String, Device)>,
}
#[derive(Clone, Default)]
pub(super) struct Selection {
    memory: Arc<Mutex<Memory>>,
    revision: u64,
}
impl Selection {
    pub fn reset(&mut self) {
        let mut memory = self.memory.lock().unwrap_or_else(|e| e.into_inner());
        memory.revision = memory.revision.wrapping_add(1);
        memory.selected = None;
        self.revision = memory.revision;
    }
    pub fn for_binding(&mut self, binding: &Binding) {
        let changed = self
            .memory
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .selected
            .as_ref()
            .is_some_and(|(origin, session, _)| {
                origin != &binding.origin || session != &binding.session
            });
        if changed {
            self.reset();
        }
    }
    pub fn recalled(&self, binding: &Binding) -> Result<Option<Device>, ()> {
        let memory = self.memory.lock().unwrap_or_else(|e| e.into_inner());
        if memory.revision != self.revision {
            return Err(());
        }
        Ok(memory
            .selected
            .as_ref()
            .filter(|(origin, session, _)| origin == &binding.origin && session == &binding.session)
            .map(|(_, _, device)| device.clone()))
    }
    pub fn remember(&self, binding: &Binding, device: &Device) -> Result<(), ()> {
        let mut memory = self.memory.lock().unwrap_or_else(|e| e.into_inner());
        if memory.revision != self.revision {
            return Err(());
        }
        if memory
            .selected
            .as_ref()
            .is_some_and(|(origin, session, previous)| {
                origin != &binding.origin || session != &binding.session || previous != device
            })
        {
            return Err(());
        }
        memory.selected = Some((
            binding.origin.clone(),
            binding.session.clone(),
            device.clone(),
        ));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{device, dummy_binding};
    use super::*;
    #[test]
    fn choice_is_origin_and_session_bound_and_reset_cannot_be_undone_by_old_task() {
        let mut selection = Selection::default();
        let binding = dummy_binding();
        selection.remember(&binding, &device(1)).unwrap();
        let mut repaired = binding.clone();
        repaired.request = "fresh-request".into();
        repaired.epoch += 1;
        assert!(selection.recalled(&repaired).unwrap() == Some(device(1)));
        let old = selection.clone();
        selection.reset();
        assert!(old.remember(&binding, &device(1)).is_err());
        assert!(selection.recalled(&binding).unwrap().is_none());
        selection.remember(&binding, &device(1)).unwrap();
        repaired.session = "different-backend-session".into();
        selection.for_binding(&repaired);
        assert!(selection.recalled(&repaired).unwrap().is_none());
        selection.remember(&repaired, &device(2)).unwrap();
        repaired.origin = "https://another-origin.example".into();
        selection.for_binding(&repaired);
        assert!(selection.recalled(&repaired).unwrap().is_none());
    }
}
