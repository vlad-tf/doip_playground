# Copyright 2026 Vladislav Vostrykh, Technica Engineering GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
``SessionRegistry`` in isolation — no sockets, no event loop needed.

``register``/``unregister``/``lookup`` only ever compare object identity, so
plain sentinel objects stand in for real ``EcuSession`` instances here.
"""

from __future__ import annotations

from testecu.session import SessionRegistry

SA = 0x0E00


def test_unregister_removes_the_registered_session():
    registry = SessionRegistry()
    session = object()
    registry.register(SA, session)
    registry.unregister(SA, session)
    assert registry.lookup(SA) is None


def test_unregister_is_a_noop_when_a_different_session_now_owns_the_sa():
    # Reproduces the eviction race this identity check exists for: an evicted
    # session unregisters itself, a new session registers under the same SA,
    # and only then does the evicted session's own (delayed) unregister call
    # land. Before the identity check, this second call would pop-by-key and
    # remove the *new* session's entry, leaving the SA unregistered even
    # though a live session owns it — silently defeating ISO 13400-2 §9.3
    # conflict resolution (a third connection would then be waved through
    # with no Alive Check probe at all).
    registry = SessionRegistry()
    evicted = object()
    current = object()

    registry.register(SA, evicted)
    registry.unregister(SA, evicted)      # evict() unregisters immediately
    registry.register(SA, current)        # the new session takes the SA
    registry.unregister(SA, evicted)      # the evicted session's delayed
                                           # run() finally calls this again

    assert registry.lookup(SA) is current


def test_unregister_with_a_session_never_registered_is_a_noop():
    registry = SessionRegistry()
    owner = object()
    stranger = object()

    registry.register(SA, owner)
    registry.unregister(SA, stranger)

    assert registry.lookup(SA) is owner


def test_unregister_of_a_different_sa_does_not_touch_this_one():
    registry = SessionRegistry()
    session = object()
    registry.register(SA, session)
    registry.unregister(SA + 1, session)
    assert registry.lookup(SA) is session
